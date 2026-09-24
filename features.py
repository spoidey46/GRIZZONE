from urllib.parse import urlparse, unquote
import ipaddress
import math
import re
import unicodedata


SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "password",
    "passwd",
    "bank",
    "banking",
    "confirm",
    "confirmation",
    "wallet",
    "payment",
    "authenticate",
    "authentication",
    "authorize",
    "authorization",
    "recover",
    "recovery",
    "unlock",
    "suspend",
    "suspended",
    "security",
    "billing",
    "invoice",
    "gift",
    "bonus",
    "reward",
    "crypto",
    "webmail",
]

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "click",
    "top",
    "work",
    "gq",
    "tk",
    "ml",
    "ga",
    "cf",
    "buzz",
    "cam",
    "rest",
    "fit",
    "country",
    "stream",
    "download",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly",
    "tiny.cc",
    "rb.gy",
}

BRAND_DOMAINS = {
    "google": {
        "google.com",
        "google.co.in",
    },
    "microsoft": {
        "microsoft.com",
        "live.com",
        "outlook.com",
    },
    "apple": {
        "apple.com",
    },
    "paypal": {
        "paypal.com",
    },
    "amazon": {
        "amazon.com",
        "amazon.in",
    },
    "facebook": {
        "facebook.com",
        "fb.com",
    },
    "instagram": {
        "instagram.com",
    },
    "whatsapp": {
        "whatsapp.com",
    },
    "netflix": {
        "netflix.com",
    },
    "steam": {
        "steampowered.com",
        "steamcommunity.com",
    },
    "linkedin": {
        "linkedin.com",
    },
    "github": {
        "github.com",
    },
    "discord": {
        "discord.com",
        "discordapp.com",
    },
    "binance": {
        "binance.com",
    },
}


MULTI_PART_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.in",
    "firm.in",
    "net.in",
    "org.in",
    "gen.in",
    "ind.in",
    "co.jp",
    "com.br",
    "com.cn",
    "com.mx",
}


def _registrable_domain(hostname):
    """
    Approximate the registrable domain without requiring
    an external public-suffix package.
    """

    parts = hostname.split(".")

    if len(parts) < 2:
        return hostname

    last_two = ".".join(parts[-2:])

    if last_two in MULTI_PART_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])

    return last_two


def _hostname_entropy(hostname):
    """
    Estimate character entropy of a hostname.
    Very random-looking hostnames can be suspicious,
    although entropy alone is never treated as proof.
    """

    cleaned = re.sub(r"[^a-zA-Z0-9]", "", hostname)

    if len(cleaned) < 12:
        return 0.0

    frequencies = {}

    for char in cleaned:
        frequencies[char] = frequencies.get(char, 0) + 1

    length = len(cleaned)

    entropy = 0.0

    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 2)


def _is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _has_unicode_or_mixed_scripts(hostname):
    if hostname.isascii():
        return False, False

    scripts = set()

    for char in hostname:
        if char.isalpha():
            name = unicodedata.name(char, "")

            if "LATIN" in name:
                scripts.add("LATIN")
            elif "CYRILLIC" in name:
                scripts.add("CYRILLIC")
            elif "GREEK" in name:
                scripts.add("GREEK")
            elif "ARABIC" in name:
                scripts.add("ARABIC")
            else:
                scripts.add("OTHER")

    mixed_scripts = len(scripts) > 1

    return True, mixed_scripts


def extract_features(url):

    original_url = url.strip()

    if not original_url.startswith(
        ("http://", "https://")
    ):
        normalized_url = "http://" + original_url
    else:
        normalized_url = original_url

    try:
        parsed = urlparse(normalized_url)
    except ValueError:
        parsed = None

    if parsed is None:
        return {
            "url_length": len(normalized_url),
            "uses_https": False,
            "dot_count": normalized_url.count("."),
            "hyphen_count": 0,
            "has_at_symbol": "@" in normalized_url,
            "uses_ip": False,
            "subdomain_count": 0,
            "suspicious_keywords": [],
            "hostname_keywords": [],
            "path_keywords": [],
            "query_keywords": [],
            "has_credentials": False,
            "has_punycode": False,
            "has_unicode": False,
            "mixed_scripts": False,
            "suspicious_tld": False,
            "tld": "",
            "nonstandard_port": False,
            "encoded_characters": "%" in normalized_url,
            "double_slash_path": False,
            "is_shortener": False,
            "brand_impersonation": [],
            "hostname_entropy": 0.0,
            "very_long_url": len(normalized_url) > 100,
            "malformed_url": True,
        }

    hostname = parsed.hostname or ""
    hostname = hostname.lower()

    path = parsed.path or ""
    query = parsed.query or ""

    decoded_url = unquote(normalized_url)

    uses_https = parsed.scheme == "https"

    url_length = len(normalized_url)

    dot_count = hostname.count(".")

    hyphen_count = hostname.count("-")

    has_at_symbol = "@" in normalized_url

    has_credentials = bool(
        parsed.username or parsed.password
    )

    uses_ip = _is_ip_address(hostname)

    domain_parts = [
        part for part in hostname.split(".") if part
    ]

    if len(domain_parts) > 2:
        subdomain_count = len(domain_parts) - 2
    else:
        subdomain_count = 0

    # -----------------------------------------
    # Keywords
    # -----------------------------------------

    lower_url = normalized_url.lower()
    lower_hostname = hostname.lower()
    lower_path = path.lower()
    lower_query = query.lower()

    found_keywords = []

    hostname_keywords = []
    path_keywords = []
    query_keywords = []

    for word in SUSPICIOUS_WORDS:

        if word in lower_url:
            found_keywords.append(word)

        if word in lower_hostname:
            hostname_keywords.append(word)

        if word in lower_path:
            path_keywords.append(word)

        if word in lower_query:
            query_keywords.append(word)

    found_keywords = sorted(set(found_keywords))
    hostname_keywords = sorted(set(hostname_keywords))
    path_keywords = sorted(set(path_keywords))
    query_keywords = sorted(set(query_keywords))

    # -----------------------------------------
    # Punycode / Unicode
    # -----------------------------------------

    has_punycode = any(
        label.startswith("xn--")
        for label in hostname.split(".")
    )

    has_unicode, mixed_scripts = _has_unicode_or_mixed_scripts(
        hostname
    )

    # -----------------------------------------
    # TLD
    # -----------------------------------------

    tld = ""

    if "." in hostname:
        tld = hostname.rsplit(".", 1)[-1]

    suspicious_tld = tld in SUSPICIOUS_TLDS

    # -----------------------------------------
    # Port
    # -----------------------------------------

    try:
        port = parsed.port
    except ValueError:
        port = None

    nonstandard_port = (
        port is not None
        and port not in (80, 443)
    )

    # -----------------------------------------
    # Encoding
    # -----------------------------------------

    encoded_characters = "%" in normalized_url

    # -----------------------------------------
    # Double slash
    # -----------------------------------------

    after_scheme = normalized_url.split(
        "://",
        1
    )[-1]

    double_slash_path = "//" in after_scheme

    # -----------------------------------------
    # URL shortener
    # -----------------------------------------

    registrable_domain = _registrable_domain(
        hostname
    )

    is_shortener = (
        registrable_domain in URL_SHORTENERS
    )

    # -----------------------------------------
    # Brand impersonation
    # -----------------------------------------

    brand_impersonation = []

    for brand, official_domains in BRAND_DOMAINS.items():

        brand_present = (
            brand in lower_hostname
        )

        if not brand_present:
            continue

        if registrable_domain in official_domains:
            continue

        brand_impersonation.append(brand)

    # -----------------------------------------
    # Random-looking hostname
    # -----------------------------------------

    hostname_entropy = _hostname_entropy(
        hostname
    )

    # -----------------------------------------
    # Malformed / unusual URL
    # -----------------------------------------

    malformed_url = (
        not hostname
        or parsed.scheme not in ("http", "https")
    )

    return {
        "url_length": url_length,
        "uses_https": uses_https,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "has_at_symbol": has_at_symbol,
        "uses_ip": uses_ip,
        "subdomain_count": subdomain_count,
        "suspicious_keywords": found_keywords,
        "hostname_keywords": hostname_keywords,
        "path_keywords": path_keywords,
        "query_keywords": query_keywords,
        "has_credentials": has_credentials,
        "has_punycode": has_punycode,
        "has_unicode": has_unicode,
        "mixed_scripts": mixed_scripts,
        "suspicious_tld": suspicious_tld,
        "tld": tld,
        "nonstandard_port": nonstandard_port,
        "encoded_characters": encoded_characters,
        "double_slash_path": double_slash_path,
        "is_shortener": is_shortener,
        "brand_impersonation": brand_impersonation,
        "hostname_entropy": hostname_entropy,
        "very_long_url": url_length > 100,
        "decoded_url": decoded_url,
        "malformed_url": malformed_url,
    }