import streamlit as st
import pandas as pd

from detector import analyze_url
from database import create_database, save_scan, get_scans


# ============================================
# DATABASE
# ============================================

create_database()


# ============================================
# PAGE CONFIGURATION
# ============================================

st.set_page_config(
    page_title="GRIZZONE",
    page_icon="🛡️",
    layout="wide"
)


# ============================================
# HEADER
# ============================================

st.title("🛡️ GRIZZONE")
st.subheader("Phishing URL Detection System")

st.write(
    "Analyze website URLs for suspicious characteristics "
    "using GRIZZONE's rule-based detection engine."
)


# ============================================
# URL SCANNER
# ============================================

st.divider()

st.subheader("🔎 Scan a Website")

url = st.text_input(
    "Enter website URL",
    placeholder="https://example.com"
)


if st.button("Scan URL"):

    if not url:

        st.warning(
            "Please enter a website URL."
        )

    else:

        # Analyze URL
        score, risk, reasons, features = analyze_url(url)

        # Save scan
        save_scan(
            url,
            score,
            risk
        )

        # ====================================
        # SCAN RESULT
        # ====================================

        st.subheader("🎯 Scan Result")

        if risk == "HIGH RISK":

            st.error(
                f"⚠️ {risk}"
            )

        elif risk == "MEDIUM RISK":

            st.warning(
                f"⚠️ {risk}"
            )

        else:

            st.success(
                f"✅ {risk}"
            )

        st.metric(
            "Risk Score",
            f"{score}/100"
        )


        # ====================================
        # ANALYSIS REASONS
        # ====================================

        st.subheader("🧠 Analysis")

        if reasons:

            for reason in reasons:

                st.write(
                    "•",
                    reason
                )

        else:

            st.write(
                "No significant suspicious indicators "
                "were detected by the current rules."
            )


        # ====================================
        # DETECTION FEATURES
        # ====================================

        st.subheader("🔍 Detection Features")

        feature_data = pd.DataFrame(
            {
                "Feature": [
                    "HTTPS",
                    "URL Length",
                    "@ Symbol",
                    "IP Address",
                    "Dots",
                    "Hyphens",
                    "Subdomains",
                    "Suspicious Keywords"
                ],

                "Value": [
                    "Yes"
                    if features["uses_https"]
                    else "No",

                    features["url_length"],

                    "Yes"
                    if features["has_at_symbol"]
                    else "No",

                    "Yes"
                    if features["uses_ip"]
                    else "No",

                    features["dot_count"],

                    features["hyphen_count"],

                    features["subdomain_count"],

                    (
                        ", ".join(
                            features["suspicious_keywords"]
                        )
                        if features["suspicious_keywords"]
                        else "None"
                    )
                ]
            }
        )

        st.table(feature_data)


# ============================================
# GET UPDATED DATABASE DATA
# ============================================

scans = get_scans()


# ============================================
# CALCULATE DASHBOARD STATISTICS
# ============================================

total_scans = len(scans)

low_risk = sum(
    1
    for scan in scans
    if scan[3] == "LOW RISK"
)

medium_risk = sum(
    1
    for scan in scans
    if scan[3] == "MEDIUM RISK"
)

high_risk = sum(
    1
    for scan in scans
    if scan[3] == "HIGH RISK"
)


# ============================================
# DASHBOARD
# ============================================

st.divider()

st.subheader("📊 Dashboard")

col1, col2, col3, col4 = st.columns(4)


with col1:

    st.metric(
        "Total Scans",
        total_scans
    )


with col2:

    st.metric(
        "Low Risk",
        low_risk
    )


with col3:

    st.metric(
        "Medium Risk",
        medium_risk
    )


with col4:

    st.metric(
        "High Risk",
        high_risk
    )


# ============================================
# RISK DISTRIBUTION
# ============================================

st.divider()

st.subheader("📈 Risk Distribution")

chart_data = pd.DataFrame(
    {
        "Risk Level": [
            "Low Risk",
            "Medium Risk",
            "High Risk"
        ],

        "Scans": [
            low_risk,
            medium_risk,
            high_risk
        ]
    }
)

st.bar_chart(
    chart_data,
    x="Risk Level",
    y="Scans"
)


# ============================================
# SCAN HISTORY
# ============================================

st.divider()

st.subheader("📋 Scan History")


if scans:

    history_data = []

    for scan in scans:

        scan_id = scan[0]
        scanned_url = scan[1]
        scan_score = scan[2]
        scan_risk = scan[3]
        scanned_at = scan[4]

        history_data.append(
            {
                "Date & Time": scanned_at,
                "URL": scanned_url,
                "Risk": scan_risk,
                "Score": scan_score
            }
        )


    history_df = pd.DataFrame(
        history_data
    )

    st.dataframe(
        history_df,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No scans have been recorded yet."
    )