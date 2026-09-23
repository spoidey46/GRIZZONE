from features import extract_features


def analyze_url(url):

    # Extract URL features
    features = extract_features(url)

    score = 0
    reasons = []

    # --------------------------------
    # HTTPS
    # --------------------------------

    if not features["uses_https"]:

        score += 15

        reasons.append(
            "The website does not use HTTPS."
        )

    # --------------------------------
    # URL LENGTH
    # --------------------------------

    if features["url_length"] > 100:

        score += 15

        reasons.append(
            "The URL is unusually long."
        )

    elif features["url_length"] > 75:

        score += 10

        reasons.append(
            "The URL is relatively long."
        )

    # --------------------------------
    # @ SYMBOL
    # --------------------------------

    if features["has_at_symbol"]:

        score += 30

        reasons.append(
            "The URL contains '@', which can hide "
            "the actual destination."
        )

    # --------------------------------
    # IP ADDRESS
    # --------------------------------

    if features["uses_ip"]:

        score += 25

        reasons.append(
            "The website uses an IP address instead "
            "of a normal domain name."
        )

    # --------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------

    keywords = features["suspicious_keywords"]

    if keywords:

        keyword_score = min(
            len(keywords) * 5,
            15
        )

        score += keyword_score

        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(keywords)
        )

    # --------------------------------
    # EXCESSIVE HYPHENS
    # --------------------------------

    if features["hyphen_count"] >= 3:

        score += 10

        reasons.append(
            "The domain contains an unusually "
            "high number of hyphens."
        )

    # --------------------------------
    # MANY SUBDOMAINS
    # --------------------------------

    if features["subdomain_count"] >= 3:

        score += 10

        reasons.append(
            "The domain contains an unusually "
            "large number of subdomains."
        )

    # --------------------------------
    # SUSPICIOUS DOUBLE SLASH
    # --------------------------------

    if "//" in url.split("://", 1)[-1]:

        score += 10

        reasons.append(
            "The URL contains an unusual "
            "double-slash pattern."
        )

    # --------------------------------
    # LIMIT SCORE
    # --------------------------------

    score = min(score, 100)

    # --------------------------------
    # RISK LEVEL
    # --------------------------------

    if score >= 60:

        risk = "HIGH RISK"

    elif score >= 30:

        risk = "MEDIUM RISK"

    else:

        risk = "LOW RISK"

    # --------------------------------
    # RETURN RESULTS
    # --------------------------------

    return score, risk, reasons, features