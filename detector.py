from features import extract_features


def analyze_url(url):

    features = extract_features(url)

    score = 0
    reasons = []

    # =====================================================
    # BASIC URL VALIDATION
    # =====================================================

    if features["malformed_url"]:
        score += 40
        reasons.append(
            "The URL appears malformed or uses an unsupported structure."
        )

    # =====================================================
    # HTTPS
    # =====================================================

    # IMPORTANT:
    # HTTPS is NOT treated as proof of safety.
    #
    # We only give a small penalty to plain HTTP because
    # HTTPS itself cannot determine whether a website is
    # legitimate.

    if not features["uses_https"]:
        score += 5
        reasons.append(
            "The website does not use HTTPS."
        )

    # =====================================================
    # URL LENGTH
    # =====================================================

    if features["url_length"] > 180:
        score += 20
        reasons.append(
            "The URL is unusually long."
        )

    elif features["url_length"] > 120:
        score += 15
        reasons.append(
            "The URL is significantly longer than typical URLs."
        )

    elif features["url_length"] > 75:
        score += 8
        reasons.append(
            "The URL is relatively long."
        )

    # =====================================================
    # @ / CREDENTIAL TRICKS
    # =====================================================

    if features["has_at_symbol"]:
        score += 30
        reasons.append(
            "The URL contains '@', which can obscure the actual destination."
        )

    if features["has_credentials"]:
        score += 25
        reasons.append(
            "The URL contains embedded username/password information."
        )

    # =====================================================
    # IP ADDRESS
    # =====================================================

    if features["uses_ip"]:
        score += 25
        reasons.append(
            "The website uses an IP address instead of a normal domain name."
        )

    # =====================================================
    # PUNYCODE / UNICODE
    # =====================================================

    if features["has_punycode"]:
        score += 20
        reasons.append(
            "The domain contains Punycode, which can be used in lookalike domains."
        )

    if features["has_unicode"]:
        score += 12
        reasons.append(
            "The domain contains non-ASCII Unicode characters."
        )

    if features["mixed_scripts"]:
        score += 25
        reasons.append(
            "The domain appears to mix different writing systems, "
            "which can indicate a lookalike domain."
        )

    # =====================================================
    # BRAND IMPERSONATION
    # =====================================================

    if features["brand_impersonation"]:

        brands = ", ".join(
            features["brand_impersonation"]
        )

        score += min(
            len(features["brand_impersonation"]) * 25,
            50
        )

        reasons.append(
            "Possible brand impersonation detected: "
            + brands
            + "."
        )

    # =====================================================
    # SUSPICIOUS TLD
    # =====================================================

    if features["suspicious_tld"]:
        score += 12

        reasons.append(
            "The domain uses a TLD frequently associated with "
            "abusive or suspicious URLs."
        )

    # =====================================================
    # NON-STANDARD PORT
    # =====================================================

    if features["nonstandard_port"]:
        score += 10

        reasons.append(
            "The URL uses a non-standard network port."
        )

    # =====================================================
    # URL ENCODING
    # =====================================================

    if features["encoded_characters"]:
        score += 8

        reasons.append(
            "The URL contains percent-encoded characters."
        )

    # =====================================================
    # SUBDOMAINS
    # =====================================================

    if features["subdomain_count"] >= 5:

        score += 18

        reasons.append(
            "The domain contains an unusually large number of subdomains."
        )

    elif features["subdomain_count"] >= 3:

        score += 10

        reasons.append(
            "The domain contains multiple nested subdomains."
        )

    # =====================================================
    # HYPHENS
    # =====================================================

    if features["hyphen_count"] >= 5:

        score += 15

        reasons.append(
            "The domain contains an unusually high number of hyphens."
        )

    elif features["hyphen_count"] >= 3:

        score += 8

        reasons.append(
            "The domain contains several hyphens."
        )

    # =====================================================
    # SUSPICIOUS KEYWORDS
    # =====================================================

    keywords = features["suspicious_keywords"]

    if keywords:

        keyword_score = min(
            len(keywords) * 3,
            15
        )

        score += keyword_score

        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(keywords)
            + "."
        )

    # =====================================================
    # KEYWORDS IN HOSTNAME
    # =====================================================

    hostname_keywords = features[
        "hostname_keywords"
    ]

    if hostname_keywords:

        hostname_score = min(
            len(hostname_keywords) * 6,
            18
        )

        score += hostname_score

        reasons.append(
            "Suspicious security-related terms appear "
            "inside the domain name: "
            + ", ".join(hostname_keywords)
            + "."
        )

    # =====================================================
    # DOUBLE SLASH
    # =====================================================

    if features["double_slash_path"]:

        score += 10

        reasons.append(
            "The URL contains an unusual double-slash pattern "
            "after the domain."
        )

    # =====================================================
    # URL SHORTENER
    # =====================================================

    if features["is_shortener"]:

        score += 10

        reasons.append(
            "The URL uses a known URL-shortening service, "
            "which hides the final destination."
        )

    # =====================================================
    # HOSTNAME ENTROPY
    # =====================================================

    if features["hostname_entropy"] >= 4.0:

        score += 10

        reasons.append(
            "The hostname contains a high level of character randomness."
        )

    # =====================================================
    # COMBINATION SIGNALS
    # =====================================================

    strong_signals = 0

    if features["brand_impersonation"]:
        strong_signals += 1

    if features["has_punycode"] or features["mixed_scripts"]:
        strong_signals += 1

    if features["uses_ip"]:
        strong_signals += 1

    if features["has_at_symbol"]:
        strong_signals += 1

    if features["has_credentials"]:
        strong_signals += 1

    if strong_signals >= 2:

        score += 15

        reasons.append(
            "Multiple high-risk URL indicators appear together."
        )

    # =====================================================
    # FINAL SCORE
    # =====================================================

    score = min(score, 100)

    # =====================================================
    # RISK CLASSIFICATION
    # =====================================================

    if score >= 60:
        risk = "HIGH RISK"

    elif score >= 30:
        risk = "MEDIUM RISK"

    else:
        risk = "LOW RISK"

    return score, risk, reasons, features