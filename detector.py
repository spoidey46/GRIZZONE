from difflib import SequenceMatcher
import ipaddress
import re
from urllib.parse import urlparse

from features import extract_features, BRAND_DOMAINS, _registrable_domain


def _validate_url(value):
    """Reject arbitrary text before feature extraction or network lookups."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Enter a website URL, such as https://example.com.")

    raw = value.strip()
    if any(ch.isspace() or ord(ch) < 32 for ch in raw):
        raise ValueError("That doesn't look like a valid URL. Remove spaces and enter a domain such as example.com.")

    candidate = raw if re.match(r"^https?://", raw, re.IGNORECASE) else "https://" + raw
    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname
        # Accessing .port also validates malformed port syntax.
        _ = parsed.port
    except ValueError:
        raise ValueError("The URL format is invalid. Check the domain and port.")

    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc or not hostname:
        raise ValueError("Enter a complete website address, such as https://example.com.")

    hostname = hostname.rstrip(".").lower()
    if len(hostname) > 253:
        raise ValueError("The domain name is too long to be valid.")

    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    if not is_ip:
        try:
            ascii_host = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError("The domain contains invalid international characters.")

        labels = ascii_host.split(".")
        if len(labels) < 2:
            raise ValueError("Enter a fully qualified domain, such as example.com — not a word or search term.")
        label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
        if any(len(label) > 63 or not label_pattern.fullmatch(label) for label in labels):
            raise ValueError("The domain name contains an invalid label.")
        tld = labels[-1]
        if len(tld) < 2 or not re.fullmatch(r"[a-z0-9-]+", tld):
            raise ValueError("The domain suffix does not look valid.")

    return raw


def _typosquat_brands(hostname):
    """Find close brand lookalikes in the registrable domain, not in URL paths."""
    registrable = _registrable_domain(hostname)
    label = registrable.split(".")[0]
    matches = []
    for brand, official_domains in BRAND_DOMAINS.items():
        if registrable in official_domains or label == brand:
            continue
        # Only flag close spellings of a known brand; generic keyword presence
        # alone is not enough to claim impersonation.
        candidates = [part for part in re.split(r"[-_]", label) if part]
        candidates.append(label)
        similarity = max((SequenceMatcher(None, part, brand).ratio() for part in candidates), default=0.0)
        if any(len(part) >= 4 for part in candidates) and similarity >= 0.78:
            matches.append(brand)
    return sorted(set(matches))


def analyze_url(url):
    url = _validate_url(url)
    features = extract_features(url)
    score = 0
    reasons = []

    hostname = (urlparse(url if "://" in url else "https://" + url).hostname or "").lower()
    typo_brands = _typosquat_brands(hostname)
    all_brand_flags = sorted(set(features.get("brand_impersonation", []) + typo_brands))

    # Transport is a weak signal only: HTTPS is not proof of legitimacy.
    if not features["uses_https"]:
        score += 8
        reasons.append("The URL uses HTTP rather than HTTPS; traffic may not be encrypted.")

    if features["url_length"] > 180:
        score += 15
        reasons.append("The URL is unusually long.")
    elif features["url_length"] > 120:
        score += 10
        reasons.append("The URL is significantly longer than typical URLs.")
    elif features["url_length"] > 75:
        score += 5
        reasons.append("The URL is relatively long.")

    if features["has_at_symbol"]:
        score += 35
        reasons.append("The URL contains '@', which can disguise the actual destination.")
    if features["has_credentials"]:
        score += 30
        reasons.append("The URL embeds username or password information.")
    if features["uses_ip"]:
        score += 25
        reasons.append("The site uses a raw IP address instead of a normal domain.")
    if features["has_punycode"]:
        score += 25
        reasons.append("The domain uses Punycode, which can conceal lookalike characters.")
    if features["mixed_scripts"]:
        score += 30
        reasons.append("The domain mixes writing systems, a strong lookalike-domain warning.")
    elif features["has_unicode"]:
        score += 10
        reasons.append("The domain contains non-ASCII characters; inspect the displayed domain carefully.")

    if all_brand_flags:
        score += min(35 + (10 if typo_brands else 0), 45)
        reasons.append("Possible brand impersonation / typosquatting: " + ", ".join(all_brand_flags) + ".")

    if features["suspicious_tld"]:
        score += 12
        reasons.append("The domain uses a TLD that appears frequently in abusive URL campaigns; this is a weak signal by itself.")
    if features["nonstandard_port"]:
        score += 10
        reasons.append("The URL uses a non-standard network port.")

    if features["encoded_characters"]:
        score += 4
        reasons.append("The URL contains percent-encoded characters.")
    if features["subdomain_count"] >= 5:
        score += 15
        reasons.append("The domain has an unusually large number of subdomains.")
    elif features["subdomain_count"] >= 3:
        score += 8
        reasons.append("The domain has multiple nested subdomains.")
    if features["hyphen_count"] >= 5:
        score += 12
        reasons.append("The hostname contains an unusually high number of hyphens.")
    elif features["hyphen_count"] >= 3:
        score += 6
        reasons.append("The hostname contains several hyphens.")

    # Hostname terms matter more than path terms. A legitimate /login page
    # should not be treated like a domain named account-verify-paypal.example.
    hostname_keywords = features.get("hostname_keywords", [])
    path_keywords = features.get("path_keywords", [])
    if hostname_keywords:
        score += min(len(hostname_keywords) * 8, 24)
        reasons.append("Security / account-related terms appear in the hostname: " + ", ".join(hostname_keywords) + ".")
    if path_keywords:
        score += min(len(path_keywords) * 2, 6)
        reasons.append("The URL path contains terms commonly used in credential or payment lures: " + ", ".join(path_keywords) + ".")

    if features["double_slash_path"]:
        score += 8
        reasons.append("The path contains an unusual double-slash pattern.")
    if features["is_shortener"]:
        score += 8
        reasons.append("The URL uses a shortening service, so the final destination is obscured.")
    if features["hostname_entropy"] >= 4.0:
        score += 8
        reasons.append("The hostname has unusually high character randomness.")

    # Correlated signals should not be blindly counted twice. Add a modest
    # combination penalty only when multiple independent strong indicators exist.
    strong_signals = sum((
        bool(all_brand_flags),
        bool(features["has_punycode"] or features["mixed_scripts"]),
        bool(features["uses_ip"]),
        bool(features["has_at_symbol"] or features["has_credentials"]),
    ))
    if strong_signals >= 2:
        score += 12
        reasons.append("Multiple independent high-risk URL indicators occur together.")

    score = min(int(score), 100)
    if score >= 50:
        risk = "HIGH RISK"
    elif score >= 20:
        risk = "MEDIUM RISK"
    else:
        risk = "LOW RISK"

    if not reasons:
        reasons.append("No strong URL-structure warning signs were detected. This is not proof that the website is legitimate or safe.")

    return score, risk, reasons, features
