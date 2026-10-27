"""Passive domain intelligence for GRIZZONE.

Queries RDAP registration metadata, resolves DNS, checks TLS metadata and can
query VirusTotal when VT_API_KEY is configured. Does not fetch the target page.
"""
import ipaddress
import os
import socket
import ssl
from urllib.parse import urlparse, quote
import requests

TIMEOUT = 5
USER_AGENT = "GRIZZONE-URL-Intelligence/1.0"

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

def inspect_domain(url, features=None):
    parsed = urlparse(url if "://" in url else "https://" + url)
    host = (parsed.hostname or "").lower().strip(".")
    if not host:
        raise ValueError("Enter a valid URL with a hostname.")
    result = {"domain": host, "dns": "Unavailable", "tls": "Not checked", "reputation": "Not configured — set VT_API_KEY to enable VirusTotal", "notes": []}
    try:
        response = requests.get("https://rdap.org/domain/" + quote(host, safe=".-"), timeout=TIMEOUT, headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"})
        if response.ok:
            data = response.json()
            events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
            result["created"] = events.get("registration", "Not disclosed")
            result["updated"] = events.get("last changed", "Not disclosed")
            result["expires"] = events.get("expiration", "Not disclosed")
            result["registrar"] = "Registration data returned by RDAP" if data else "Not disclosed"
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
    vt_key = os.environ.get("VT_API_KEY", "").strip()
    if vt_key:
        try:
            vt = requests.get("https://www.virustotal.com/api/v3/domains/" + quote(host, safe=".-"), timeout=TIMEOUT, headers={"x-apikey": vt_key, "User-Agent": USER_AGENT})
            if vt.status_code == 200:
                stats = vt.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                result["reputation"] = "VirusTotal: {} malicious, {} suspicious, {} harmless, {} undetected".format(stats.get("malicious", 0), stats.get("suspicious", 0), stats.get("harmless", 0), stats.get("undetected", 0))
            elif vt.status_code == 404:
                result["reputation"] = "VirusTotal has no domain report available"
            elif vt.status_code == 429:
                result["reputation"] = "VirusTotal rate limit reached"
                result["notes"].append("VirusTotal rate limit reached; reputation is inconclusive.")
            else:
                result["reputation"] = "VirusTotal lookup unavailable (HTTP {})".format(vt.status_code)
        except (requests.RequestException, ValueError, TypeError):
            result["reputation"] = "VirusTotal lookup failed; reputation is inconclusive"
    result["notes"].append("Domain age and HTTPS are context only; neither proves a site is safe.")
    return result
