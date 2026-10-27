"""Passive domain intelligence for GRIZZONE.

This module does not fetch or render the submitted web page. It queries RDAP
metadata and resolves DNS. TLS checks are deliberately metadata-only and
restricted to public DNS results; all external lookups can fail gracefully.
"""
import ipaddress
import json
import socket
import ssl
from urllib.parse import urlparse
import requests

TIMEOUT = 5
USER_AGENT = "GRIZZONE-URL-Intelligence/1.0"

def _public_ips(host):
    found = set()
    try:
        for result in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
            ip = result[4][0].split("%")[0]
            parsed = ipaddress.ip_address(ip)
            if parsed.is_global:
                found.add(ip)
    except (OSError, ValueError):
        pass
    return sorted(found)

def inspect_domain(url, features=None):
    parsed = urlparse(url if "://" in url else "https://" + url)
    host = (parsed.hostname or "").lower().strip(".")
    if not host:
        raise ValueError("Enter a valid URL with a hostname.")
    result = {"domain": host, "dns": "Unavailable", "tls": "Not checked", "reputation": "Not configured", "notes": []}
    # RDAP lookup uses a public metadata service; it does not visit the target page.
    try:
        response = requests.get("https://rdap.org/domain/" + host, timeout=TIMEOUT,
                                headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"})
        if response.ok:
            data = response.json()
            events = {event.get("eventAction"): event.get("eventDate") for event in data.get("events", [])}
            result["registrar"] = (data.get("entities") or [{}])[0].get("vcardArray", [None, []])[1][0][3] if data.get("entities") else "Not disclosed"
            result["created"] = events.get("registration", "Not disclosed")
            result["updated"] = events.get("last changed", "Not disclosed")
            result["expires"] = events.get("expiration", "Not disclosed")
        else:
            result["notes"].append("Registration records were unavailable from RDAP.")
    except (requests.RequestException, ValueError, KeyError, TypeError, IndexError):
        result["notes"].append("RDAP lookup failed or returned incomplete data.")
    ips = _public_ips(host)
    if ips:
        result["dns"] = ", ".join(ips[:8])
    else:
        result["notes"].append("No public DNS address was resolved; the host may be unavailable or use private/non-public addressing.")
    # Only attempt TLS to public-resolving hostnames, using a short timeout.
    if parsed.scheme == "https" and ips:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ips[0], 443), timeout=TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    not_after = cert.get("notAfter", "unknown expiry")
                    result["tls"] = "Valid certificate presented; expires " + not_after
        except (OSError, ssl.SSLError, ValueError):
            result["tls"] = "Certificate connection failed or could not be validated"
            result["notes"].append("TLS could not be verified from this environment.")
    elif parsed.scheme != "https":
        result["tls"] = "URL uses HTTP, not HTTPS"
    # External reputation APIs require keys; do not imply they were queried if not configured.
    result["reputation"] = "Not configured — no reputation API key supplied"
    result["notes"].append("Domain age and HTTPS are context only; neither proves a site is safe.")
    return result
