"""Passive domain and website-profile intelligence for GRIZZONE.

Queries RDAP, DNS, TLS, optional VirusTotal, and bounded static HTML metadata.
Website profile fields are claims published by the site, not proof of identity.
"""
import ipaddress
import json
import os
import socket
import ssl
from html.parser import HTMLParser
from urllib.parse import urlparse, quote, urlunparse

import requests

TIMEOUT = 5
MAX_PAGE_BYTES = 1_000_000
USER_AGENT = "GRIZZONE-URL-Intelligence/1.1"


def _public_ips(host):
    found = set()
    try:
        for result in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
            ip = result[4][0].split("%")[0]
            if ipaddress.ip_address(ip).is_global:
                found.add(ip)
    except (OSError, ValueError):
        pass
    return sorted(found)


def _vcard_name(entity):
    card = entity.get("vcardArray", [])
    if len(card) > 1 and isinstance(card[1], list):
        for item in card[1]:
            if len(item) >= 4 and item[0] == "fn":
                return str(item[3])
    return ""


class _PageMetadata(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title_parts = []
        self.in_title = False
        self.meta = {}
        self.jsonld_parts = []
        self.in_jsonld = False
        self.current_jsonld = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag.lower() == "title":
            self.in_title = True
        if tag.lower() == "meta":
            key = (attrs.get("property") or attrs.get("name") or "").strip().lower()
            value = (attrs.get("content") or "").strip()
            if key and value:
                self.meta[key] = value[:1000]
        if tag.lower() == "script" and "ld+json" in attrs.get("type", "").lower():
            self.in_jsonld = True
            self.current_jsonld = []

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False
        if tag.lower() == "script" and self.in_jsonld:
            self.jsonld_parts.append("".join(self.current_jsonld))
            self.current_jsonld = []
            self.in_jsonld = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)
        if self.in_jsonld:
            self.current_jsonld.append(data)


def _flatten_jsonld(value):
    if isinstance(value, list):
        for item in value:
            yield from _flatten_jsonld(item)
    elif isinstance(value, dict):
        yield value
        graph = value.get("@graph")
        if graph:
            yield from _flatten_jsonld(graph)


def _website_profile(url, host):
    profile = {
        "status": "Website profile not available",
        "title": "Not found",
        "description": "Not found",
        "organization": "Not found",
        "legal_name": "Not found",
        "founder": "Not found",
        "founding_date": "Not found",
        "published_website": "Not found",
        "official_links": [],
    }
    parsed = urlparse(url if "://" in url else "https://" + url)
    if parsed.scheme not in ("http", "https") or not host or not _public_ips(host):
        profile["status"] = "Skipped: host did not resolve to a public IP address"
        return profile

    # Inspect static HTML only: no JavaScript execution, downloads, or redirects.
    request_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))
    try:
        with requests.get(
            request_url,
            timeout=TIMEOUT,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html"},
            allow_redirects=False,
            stream=True,
        ) as response:
            if response.is_redirect:
                profile["status"] = "Skipped: site redirected; no redirect was followed"
                return profile
            if response.status_code >= 400:
                profile["status"] = "Page unavailable (HTTP {})".format(response.status_code)
                return profile
            content_type = response.headers.get("Content-Type", "").lower()
            if "text/html" not in content_type:
                profile["status"] = "Skipped: response is not HTML"
                return profile
            chunks = []
            total = 0
            for chunk in response.iter_content(chunk_size=16384):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_PAGE_BYTES:
                    profile["status"] = "Skipped: HTML exceeds the 1 MB inspection limit"
                    return profile
                chunks.append(chunk)
            raw = b"".join(chunks)
            encoding = response.encoding or "utf-8"
            page = raw.decode(encoding, errors="replace")
    except (requests.RequestException, OSError, ValueError, LookupError):
        profile["status"] = "Could not retrieve public page metadata"
        return profile

    parser = _PageMetadata()
    try:
        parser.feed(page)
    except Exception:
        profile["status"] = "Retrieved page, but its metadata could not be parsed"
        return profile

    meta = parser.meta
    profile["title"] = (" ".join("".join(parser.title_parts).split()) or
                        meta.get("og:title") or meta.get("twitter:title") or "Not found")
    profile["description"] = (meta.get("description") or meta.get("og:description") or
                              meta.get("twitter:description") or "Not found")
    profile["published_website"] = meta.get("og:url", "Not found")
    profile["status"] = "Static page metadata retrieved; organization claims are not independently verified"

    for raw_json in parser.jsonld_parts:
        try:
            decoded = json.loads(raw_json)
        except (ValueError, TypeError):
            continue
        for item in _flatten_jsonld(decoded):
            kinds = item.get("@type", [])
            if isinstance(kinds, str):
                kinds = [kinds]
            kind_text = " ".join(str(k) for k in kinds).lower()
            if not any(word in kind_text for word in ("organization", "corporation", "localbusiness", "person")):
                continue
            if profile["organization"] == "Not found":
                profile["organization"] = str(item.get("name") or item.get("alternateName") or "Not found")
                profile["legal_name"] = str(item.get("legalName") or "Not found")
                founder = item.get("founder")
                if isinstance(founder, dict):
                    founder = founder.get("name")
                elif isinstance(founder, list):
                    founder = ", ".join(str(x.get("name", x)) if isinstance(x, dict) else str(x) for x in founder)
                profile["founder"] = str(founder or "Not found")
                profile["founding_date"] = str(item.get("foundingDate") or "Not found")
                site_url = item.get("url")
                if isinstance(site_url, dict):
                    site_url = site_url.get("@id") or site_url.get("url")
                if site_url:
                    profile["published_website"] = str(site_url)
                links = item.get("sameAs", [])
                if isinstance(links, str):
                    links = [links]
                if isinstance(links, list):
                    profile["official_links"] = [str(link) for link in links[:8] if isinstance(link, str)]
                break
        if profile["organization"] != "Not found":
            break

    if profile["organization"] == "Not found":
        org_hint = meta.get("og:site_name")
        if org_hint:
            profile["organization"] = org_hint + " (site metadata)"
    if not profile["official_links"]:
        same_as = meta.get("sameas")
        if same_as:
            profile["official_links"] = [same_as]
    return profile


def inspect_domain(url, features=None):
    parsed = urlparse(url if "://" in url else "https://" + url)
    host = (parsed.hostname or "").lower().strip(".")
    if not host:
        raise ValueError("Enter a valid URL with a hostname.")
    result = {
        "domain": host,
        "dns": "Unavailable",
        "tls": "Not checked",
        "reputation": "Not configured — set VT_API_KEY to enable VirusTotal",
        "notes": [],
    }
    try:
        response = requests.get(
            "https://rdap.org/domain/" + quote(host, safe=".-"),
            timeout=TIMEOUT,
            headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"},
        )
        if response.ok:
            data = response.json()
            events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
            result["created"] = events.get("registration", "Not disclosed")
            result["updated"] = events.get("last changed", "Not disclosed")
            result["expires"] = events.get("expiration", "Not disclosed")
            registrar = ""
            for entity in data.get("entities", []):
                if "registrar" in entity.get("roles", []):
                    registrar = _vcard_name(entity)
                    if registrar:
                        break
            result["registrar"] = registrar or "Not disclosed in RDAP response"
        else:
            result["notes"].append("Registration records were unavailable from RDAP.")
    except (requests.RequestException, ValueError, KeyError, TypeError):
        result["notes"].append("RDAP lookup failed or returned incomplete data.")

    ips = _public_ips(host)
    if ips:
        result["dns"] = ", ".join(ips[:8])
    else:
        result["notes"].append("No public DNS address was resolved.")

    if parsed.scheme == "https" and ips:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ips[0], 443), timeout=TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    result["tls"] = "Valid certificate presented; expires " + tls.getpeercert().get("notAfter", "unknown")
        except (OSError, ssl.SSLError, ValueError):
            result["tls"] = "Certificate connection failed or could not be validated"
            result["notes"].append("TLS could not be verified from this environment.")
    elif parsed.scheme != "https":
        result["tls"] = "URL uses HTTP, not HTTPS"

    result["site_profile"] = _website_profile(url, host)

    vt_key = os.environ.get("VT_API_KEY", "").strip()
    if vt_key:
        try:
            vt = requests.get(
                "https://www.virustotal.com/api/v3/domains/" + quote(host, safe=".-"),
                timeout=TIMEOUT,
                headers={"x-apikey": vt_key, "User-Agent": USER_AGENT},
            )
            if vt.status_code == 200:
                stats = vt.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                result["reputation"] = "VirusTotal: {} malicious, {} suspicious, {} harmless, {} undetected".format(
                    stats.get("malicious", 0), stats.get("suspicious", 0),
                    stats.get("harmless", 0), stats.get("undetected", 0)
                )
            elif vt.status_code == 404:
                result["reputation"] = "VirusTotal has no domain report available"
            elif vt.status_code == 429:
                result["reputation"] = "VirusTotal rate limit reached"
                result["notes"].append("VirusTotal rate limit reached; reputation is inconclusive.")
            else:
                result["reputation"] = "VirusTotal lookup unavailable (HTTP {})".format(vt.status_code)
        except (requests.RequestException, ValueError, TypeError):
            result["reputation"] = "VirusTotal lookup failed; reputation is inconclusive"

    result["notes"].append("Company/founder details are shown only when published in page metadata; these claims are not independently verified.")
    result["notes"].append("Domain age and HTTPS are context only; neither proves a site is safe.")
    return result
