from urllib.parse import urlparse
import re


def extract_features(url):

    # Clean the URL
    url = url.strip()

    # Add protocol if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    hostname = hostname.lower()

    # Check whether HTTPS is being used
    uses_https = parsed.scheme == "https"

    # URL length
    url_length = len(url)

    # Number of dots
    dot_count = url.count(".")

    # Number of hyphens
    hyphen_count = hostname.count("-")

    # Check for @ symbol
    has_at_symbol = "@" in url

    # Check whether hostname is an IP address
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    uses_ip = bool(
        re.match(ip_pattern, hostname)
    )

    # Count subdomains
    domain_parts = hostname.split(".")

    if len(domain_parts) > 2:
        subdomain_count = len(domain_parts) - 2
    else:
        subdomain_count = 0

    # Suspicious keywords
    suspicious_words = [
        "login",
        "signin",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "bank",
        "confirm",
        "wallet",
        "payment",
        "authenticate"
    ]

    found_keywords = []

    for word in suspicious_words:

        if word in url.lower():

            found_keywords.append(word)

    return {
        "url_length": url_length,
        "uses_https": uses_https,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "has_at_symbol": has_at_symbol,
        "uses_ip": uses_ip,
        "subdomain_count": subdomain_count,
        "suspicious_keywords": found_keywords
    }