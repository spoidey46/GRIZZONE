import time

import pandas as pd
import streamlit as st

from database import create_database, save_scan, get_scans
from detector import analyze_url


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="GRIZZONE",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# =========================================================
# DATABASE
# =========================================================

create_database()


# =========================================================
# SESSION STATE
# =========================================================

if "page" not in st.session_state:
    st.session_state.page = "SCANNER"

if "last_scan" not in st.session_state:
    st.session_state.last_scan = None


# =========================================================
# GLOBAL CSS
# =========================================================

st.markdown(
    """
    <style>

    /* =========================
       GLOBAL
       ========================= */

    html, body, .stApp {
        background:
            radial-gradient(circle at 15% 10%, rgba(50, 80, 180, 0.12), transparent 28%),
            radial-gradient(circle at 85% 20%, rgba(120, 50, 220, 0.10), transparent 25%),
            #05070d !important;

        color: #e9f3ff !important;

        user-select: none !important;
        -webkit-user-select: none !important;

        cursor: default !important;
    }

    .stApp {
        min-height: 100vh;
    }

    .block-container {
        max-width: 1200px;
        padding-top: 1.5rem;
        padding-bottom: 3rem;
    }

    /* Prevent text-caret everywhere except real inputs */

    p, h1, h2, h3, h4, h5, h6,
    span, div, label, strong, small {
        cursor: default;
        user-select: none;
        -webkit-user-select: none;
    }

    /* =========================
       REAL INPUTS
       ========================= */

    input,
    textarea,
    [contenteditable="true"] {
        cursor: text !important;
        user-select: text !important;
        -webkit-user-select: text !important;
    }

    /* =========================
       BUTTONS
       ========================= */

    button {
        cursor: pointer !important;
        user-select: none !important;
        -webkit-user-select: none !important;
    }

    /* =========================
       NAVIGATION
       ========================= */

    [data-testid="stRadio"] {
        margin-top: 0.25rem;
    }

    [data-testid="stRadio"] > div {
        width: 100%;
    }

    [data-testid="stRadio"] div[role="radiogroup"] {
        display: flex !important;
        justify-content: flex-end;
        gap: 8px;
    }

    [data-testid="stRadio"] label {
        cursor: pointer !important;
        user-select: none !important;
        -webkit-user-select: none !important;

        padding: 7px 12px !important;
        border-radius: 8px !important;

        border: 1px solid transparent !important;

        transition:
            background 0.2s ease,
            border 0.2s ease,
            color 0.2s ease,
            transform 0.2s ease;
    }

    [data-testid="stRadio"] label:hover {
        background: rgba(70, 210, 255, 0.07) !important;
        border-color: rgba(70, 210, 255, 0.18) !important;
        transform: translateY(-1px);
    }

    [data-testid="stRadio"] label:has(input:checked) {
        color: #6de7ff !important;
        background: rgba(70, 210, 255, 0.08) !important;
        border-color: rgba(70, 210, 255, 0.28) !important;
        box-shadow: 0 0 18px rgba(70, 210, 255, 0.08);
    }

    [data-testid="stRadio"] input {
        display: none !important;
    }

    [data-testid="stRadio"] [data-baseweb="radio"] {
        display: none !important;
    }

    /* =========================
       TEXT INPUT
       ========================= */

    [data-testid="stTextInput"] input {
        background: rgba(10, 16, 28, 0.88) !important;
        border: 1px solid rgba(90, 150, 255, 0.28) !important;
        border-radius: 12px !important;

        color: #ecf7ff !important;
        font-size: 16px !important;

        padding: 14px 16px !important;

        box-shadow:
            inset 0 0 20px rgba(30, 100, 200, 0.04),
            0 0 20px rgba(30, 120, 255, 0.03) !important;

        transition:
            border 0.2s ease,
            box-shadow 0.2s ease;
    }

    [data-testid="stTextInput"] input:focus {
        border-color: rgba(80, 220, 255, 0.65) !important;

        box-shadow:
            0 0 0 1px rgba(80, 220, 255, 0.15),
            0 0 25px rgba(80, 200, 255, 0.10) !important;
    }

    [data-testid="stTextInput"] label {
        color: #90a6c3 !important;
    }

    /* =========================
       MAIN BUTTON
       ========================= */

    .scan-button button {
        width: 100% !important;

        background:
            linear-gradient(
                135deg,
                rgba(39, 180, 255, 0.95),
                rgba(102, 74, 255, 0.95)
            ) !important;

        color: white !important;

        border: 1px solid rgba(120, 230, 255, 0.35) !important;
        border-radius: 12px !important;

        font-weight: 700 !important;
        letter-spacing: 1px !important;

        min-height: 48px !important;

        box-shadow:
            0 0 25px rgba(50, 150, 255, 0.12) !important;

        transition:
            transform 0.2s ease,
            box-shadow 0.2s ease;
    }

    .scan-button button:hover {
        transform: translateY(-2px) !important;

        box-shadow:
            0 0 35px rgba(70, 190, 255, 0.22) !important;
    }

    /* =========================
       METRICS
       ========================= */

    [data-testid="stMetric"] {
        background: rgba(10, 16, 28, 0.70) !important;

        border: 1px solid rgba(90, 140, 220, 0.16) !important;

        border-radius: 14px !important;

        padding: 18px !important;

        box-shadow:
            inset 0 0 30px rgba(40, 90, 180, 0.025);
    }

    [data-testid="stMetricLabel"] {
        color: #8195b2 !important;
    }

    [data-testid="stMetricValue"] {
        color: #eaf7ff !important;
    }

    /* =========================
       DATAFRAME
       ========================= */

    [data-testid="stDataFrame"] {
        border: 1px solid rgba(90, 140, 220, 0.15);
        border-radius: 12px;
        overflow: hidden;
    }

    /* =========================
       DIVIDERS
       ========================= */

    hr {
        border-color: rgba(100, 150, 220, 0.12) !important;
    }

    /* =========================
       REMOVE STREAMLIT EXCESS
       ========================= */

    #MainMenu {
        visibility: hidden;
    }

    footer {
        visibility: hidden;
    }

    header {
        background: transparent !important;
    }

    /* =========================
       ANIMATIONS
       ========================= */

    @keyframes pulseGlow {
        0%, 100% {
            opacity: 0.55;
            transform: scale(1);
        }

        50% {
            opacity: 1;
            transform: scale(1.04);
        }
    }

    @keyframes floatCore {
        0%, 100% {
            transform: translateY(0px);
        }

        50% {
            transform: translateY(-5px);
        }
    }

    @keyframes scanLine {
        0% {
            transform: translateX(-100%);
        }

        100% {
            transform: translateX(100%);
        }
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# NAVIGATION HEADER
# =========================================================

left, right = st.columns([1.05, 2.4])

with left:
    st.html(
        """
        <div style="
            display:flex;
            align-items:center;
            gap:12px;
            padding-top:4px;
        ">

            <div style="
                width:38px;
                height:38px;
                border-radius:11px;

                display:flex;
                align-items:center;
                justify-content:center;

                background:
                    radial-gradient(
                        circle,
                        rgba(90,220,255,0.35),
                        rgba(90,80,255,0.12)
                    );

                border:1px solid rgba(100,220,255,0.28);

                box-shadow:
                    0 0 22px rgba(80,180,255,0.15);
            ">
                <span style="
                    color:#72eaff;
                    font-size:20px;
                    font-weight:800;
                ">◈</span>
            </div>

            <div>
                <div style="
                    color:#f1f8ff;
                    font-size:20px;
                    font-weight:800;
                    letter-spacing:3px;
                ">
                    GRIZZONE
                </div>

                <div style="
                    color:#607895;
                    font-size:9px;
                    letter-spacing:2px;
                    margin-top:2px;
                ">
                    URL THREAT ANALYSIS
                </div>
            </div>

        </div>
        """
    )


with right:
    page = st.radio(
        "Navigation",
        ["SCANNER", "HISTORY", "ANALYTICS", "ABOUT"],
        horizontal=True,
        label_visibility="collapsed",
        key="page",
    )


st.divider()


# =========================================================
# HELPERS
# =========================================================

def risk_color(risk):
    if risk == "HIGH RISK":
        return "#ff5577"

    if risk == "MEDIUM RISK":
        return "#ffbf5f"

    return "#54e6b1"


def render_section_title(title, subtitle):
    st.html(
        f"""
        <div style="
            margin-top:12px;
            margin-bottom:22px;
        ">

            <div style="
                font-size:12px;
                color:#5e7da5;
                letter-spacing:3px;
                margin-bottom:7px;
            ">
                SYSTEM MODULE
            </div>

            <div style="
                font-size:30px;
                font-weight:800;
                letter-spacing:1px;
                color:#edf7ff;
            ">
                {title}
            </div>

            <div style="
                margin-top:6px;
                color:#7890ad;
                font-size:13px;
            ">
                {subtitle}
            </div>

        </div>
        """
    )


def render_scan_result(scan):
    score = scan["score"]
    risk = scan["risk"]
    reasons = scan["reasons"]
    features = scan["features"]

    color = risk_color(risk)

    st.html(
        f"""
        <div style="
            margin-top:28px;
            padding:25px;

            border-radius:18px;

            background:
                linear-gradient(
                    145deg,
                    rgba(12,20,35,0.96),
                    rgba(7,11,21,0.96)
                );

            border:1px solid {color}35;

            box-shadow:
                0 0 35px {color}0d,
                inset 0 0 30px rgba(80,130,220,0.025);
        ">

            <div style="
                display:flex;
                justify-content:space-between;
                align-items:center;
                gap:20px;
                flex-wrap:wrap;
            ">

                <div>

                    <div style="
                        color:#607895;
                        font-size:10px;
                        letter-spacing:2px;
                        margin-bottom:8px;
                    ">
                        ANALYSIS COMPLETE
                    </div>

                    <div style="
                        color:{color};
                        font-size:27px;
                        font-weight:800;
                        letter-spacing:1px;
                    ">
                        {risk}
                    </div>

                    <div style="
                        color:#7187a3;
                        font-size:12px;
                        margin-top:7px;
                        word-break:break-all;
                    ">
                        {scan["url"]}
                    </div>

                </div>

                <div style="
                    width:105px;
                    height:105px;
                    border-radius:50%;

                    display:flex;
                    flex-direction:column;
                    align-items:center;
                    justify-content:center;

                    border:2px solid {color}80;

                    background:
                        radial-gradient(
                            circle,
                            {color}14,
                            transparent 68%
                        );

                    box-shadow:
                        0 0 28px {color}18;
                ">

                    <div style="
                        color:{color};
                        font-size:30px;
                        font-weight:800;
                    ">
                        {score}
                    </div>

                    <div style="
                        color:#6e839e;
                        font-size:8px;
                        letter-spacing:2px;
                    ">
                        RISK SCORE
                    </div>

                </div>

            </div>

        </div>
        """
    )

    st.html(
        """
        <div style="
            margin-top:25px;
            margin-bottom:10px;
            color:#8da6c5;
            font-size:11px;
            letter-spacing:2px;
        ">
            DETECTION SIGNALS
        </div>
        """
    )

    if reasons:
        for reason in reasons:
            st.html(
                f"""
                <div style="
                    margin:7px 0;
                    padding:12px 15px;

                    border-radius:10px;

                    background:rgba(255,255,255,0.025);
                    border:1px solid rgba(100,150,220,0.10);

                    color:#aabbd0;
                    font-size:13px;
                ">
                    <span style="
                        color:{color};
                        margin-right:9px;
                    ">
                        ●
                    </span>

                    {reason}
                </div>
                """
            )
    else:
        st.html(
            """
            <div style="
                padding:13px 15px;
                border-radius:10px;
                background:rgba(84,230,177,0.04);
                border:1px solid rgba(84,230,177,0.14);
                color:#91b7aa;
                font-size:13px;
            ">
                No suspicious indicators were detected by the current rule set.
            </div>
            """
        )

    st.html(
        """
        <div style="
            margin-top:25px;
            margin-bottom:12px;
            color:#8da6c5;
            font-size:11px;
            letter-spacing:2px;
        ">
            EXTRACTED FEATURES
        </div>
        """
    )

    feature_items = [
        ("URL LENGTH", features["url_length"]),
        ("HTTPS", "YES" if features["uses_https"] else "NO"),
        ("DOT COUNT", features["dot_count"]),
        ("HYPHENS", features["hyphen_count"]),
        ("@ SYMBOL", "YES" if features["has_at_symbol"] else "NO"),
        ("IP ADDRESS", "YES" if features["uses_ip"] else "NO"),
        ("SUBDOMAINS", features["subdomain_count"]),
        (
            "KEYWORDS",
            len(features["suspicious_keywords"])
        ),
    ]

    cols = st.columns(4)

    for index, (label, value) in enumerate(feature_items):
        with cols[index % 4]:
            st.html(
                f"""
                <div style="
                    margin-bottom:10px;
                    padding:14px;

                    border-radius:11px;

                    background:rgba(10,17,29,0.72);

                    border:1px solid rgba(80,140,220,0.12);
                ">

                    <div style="
                        color:#627a98;
                        font-size:8px;
                        letter-spacing:1.5px;
                        margin-bottom:7px;
                    ">
                        {label}
                    </div>

                    <div style="
                        color:#dceeff;
                        font-size:17px;
                        font-weight:700;
                    ">
                        {value}
                    </div>

                </div>
                """
            )


# =========================================================
# SCANNER PAGE
# =========================================================

if page == "SCANNER":

    st.html(
        """
        <div style="
            position:relative;
            text-align:center;
            padding:28px 10px 22px;
            overflow:hidden;
        ">

            <div style="
                position:absolute;
                left:50%;
                top:15px;

                width:170px;
                height:170px;

                transform:translateX(-50%);

                border-radius:50%;

                border:1px solid rgba(75,210,255,0.08);

                box-shadow:
                    0 0 60px rgba(80,100,255,0.06);

                animation:floatCore 5s ease-in-out infinite;
            "></div>

            <div style="
                position:absolute;
                left:50%;
                top:45px;

                width:90px;
                height:90px;

                transform:translateX(-50%);

                border-radius:50%;

                border:1px solid rgba(130,90,255,0.12);

                animation:pulseGlow 3s ease-in-out infinite;
            "></div>

            <div style="
                position:relative;
                z-index:2;
            ">

                <div style="
                    color:#5fddff;
                    font-size:10px;
                    letter-spacing:4px;
                    margin-bottom:12px;
                ">
                    THREAT INTELLIGENCE // ONLINE
                </div>

                <div style="
                    color:#f1f8ff;
                    font-size:43px;
                    font-weight:900;
                    letter-spacing:1px;
                    line-height:1.1;
                ">
                    See Through The URL.
                </div>

                <div style="
                    margin-top:12px;
                    color:#748ba8;
                    font-size:14px;
                ">
                    Analyze suspicious links using structural URL signals.
                </div>

            </div>

        </div>
        """
    )

    st.html(
        """
        <div style="
            margin-top:15px;
            padding:17px 20px;

            border-radius:14px;

            background:
                linear-gradient(
                    135deg,
                    rgba(18,29,49,0.82),
                    rgba(8,14,26,0.88)
                );

            border:1px solid rgba(90,170,255,0.16);

            box-shadow:
                0 0 30px rgba(40,130,255,0.04);
        ">

            <div style="
                display:flex;
                align-items:center;
                justify-content:space-between;
                gap:15px;
            ">

                <div>
                    <div style="
                        color:#e7f5ff;
                        font-size:15px;
                        font-weight:700;
                    ">
                        URL SCANNER
                    </div>

                    <div style="
                        color:#647c9b;
                        font-size:11px;
                        margin-top:4px;
                    ">
                        Enter a URL to inspect its structural risk indicators.
                    </div>
                </div>

                <div style="
                    color:#5fe5bd;
                    font-size:9px;
                    letter-spacing:2px;
                ">
                    ● READY
                </div>

            </div>

        </div>
        """
    )

    url = st.text_input(
        "URL",
        placeholder="https://example.com/login",
        label_visibility="collapsed",
    )

    scan_col, info_col = st.columns([1, 2])

    with scan_col:
        st.markdown('<div class="scan-button">', unsafe_allow_html=True)

        scan_clicked = st.button(
            "◈  ANALYZE URL",
            use_container_width=True,
        )

        st.markdown("</div>", unsafe_allow_html=True)

    with info_col:
        st.html(
            """
            <div style="
                padding:13px 15px;
                color:#607995;
                font-size:11px;
                line-height:1.5;
            ">
                GRIZZONE currently uses a rule-based prototype.
                A low score means fewer suspicious indicators were detected;
                it does not guarantee that a website is safe.
            </div>
            """
        )

    if scan_clicked:

        if not url.strip():
            st.warning("Enter a URL before starting the analysis.")

        else:

            progress = st.progress(0)

            scan_steps = [
                "Normalizing URL structure...",
                "Extracting domain signals...",
                "Inspecting suspicious patterns...",
                "Calculating risk score...",
                "Finalizing analysis...",
            ]

            for index, step in enumerate(scan_steps):

                st.caption(step)

                progress.progress(
                    int(((index + 1) / len(scan_steps)) * 100)
                )

                time.sleep(0.25)

            score, risk, reasons, features = analyze_url(url)

            save_scan(
                url,
                score,
                risk,
            )

            st.session_state.last_scan = {
                "url": url,
                "score": score,
                "risk": risk,
                "reasons": reasons,
                "features": features,
            }

            st.rerun()

    if st.session_state.last_scan:
        render_scan_result(st.session_state.last_scan)


# =========================================================
# HISTORY PAGE
# =========================================================

elif page == "HISTORY":

    render_section_title(
        "Scan History",
        "Review previously analyzed URLs stored in the local GRIZZONE database.",
    )

    scans = get_scans()

    if not scans:

        st.html(
            """
            <div style="
                margin-top:25px;
                padding:35px;
                text-align:center;

                border-radius:16px;

                background:rgba(10,17,29,0.65);
                border:1px solid rgba(90,140,220,0.12);
            ">

                <div style="
                    color:#75e5ff;
                    font-size:28px;
                ">
                    ◌
                </div>

                <div style="
                    margin-top:10px;
                    color:#c4d4e7;
                    font-weight:700;
                ">
                    No scans yet
                </div>

                <div style="
                    margin-top:6px;
                    color:#657d9b;
                    font-size:12px;
                ">
                    Analyze your first URL from the Scanner.
                </div>

            </div>
            """
        )

    else:

        df = pd.DataFrame(
            scans,
            columns=[
                "ID",
                "URL",
                "Score",
                "Risk",
                "Scanned At",
            ],
        )

        total = len(df)
        high = len(df[df["Risk"] == "HIGH RISK"])
        medium = len(df[df["Risk"] == "MEDIUM RISK"])
        low = len(df[df["Risk"] == "LOW RISK"])

        c1, c2, c3, c4 = st.columns(4)

        c1.metric("TOTAL SCANS", total)
        c2.metric("LOW RISK", low)
        c3.metric("MEDIUM RISK", medium)
        c4.metric("HIGH RISK", high)

        st.html(
            """
            <div style="
                margin-top:25px;
                margin-bottom:10px;
                color:#8da6c5;
                font-size:11px;
                letter-spacing:2px;
            ">
                RECENT ACTIVITY
            </div>
            """
        )

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
        )


# =========================================================
# ANALYTICS PAGE
# =========================================================

elif page == "ANALYTICS":

    render_section_title(
        "Analytics",
        "A high-level view of the URLs analyzed by the current detection engine.",
    )

    scans = get_scans()

    if not scans:

        st.html(
            """
            <div style="
                padding:35px;
                text-align:center;

                border-radius:16px;

                background:rgba(10,17,29,0.65);
                border:1px solid rgba(90,140,220,0.12);

                color:#7189a6;
                font-size:13px;
            ">
                Analytics will appear after you perform some URL scans.
            </div>
            """
        )

    else:

        df = pd.DataFrame(
            scans,
            columns=[
                "ID",
                "URL",
                "Score",
                "Risk",
                "Scanned At",
            ],
        )

        total = len(df)
        average_score = round(df["Score"].mean(), 1)
        highest_score = int(df["Score"].max())

        high = int((df["Risk"] == "HIGH RISK").sum())
        medium = int((df["Risk"] == "MEDIUM RISK").sum())
        low = int((df["Risk"] == "LOW RISK").sum())

        c1, c2, c3, c4 = st.columns(4)

        c1.metric(
            "TOTAL SCANS",
            total,
        )

        c2.metric(
            "AVERAGE SCORE",
            average_score,
        )

        c3.metric(
            "HIGHEST SCORE",
            highest_score,
        )

        c4.metric(
            "HIGH RISK",
            high,
        )

        st.html(
            """
            <div style="
                margin-top:28px;
                margin-bottom:10px;
                color:#8da6c5;
                font-size:11px;
                letter-spacing:2px;
            ">
                RISK DISTRIBUTION
            </div>
            """
        )

        chart_data = pd.DataFrame(
            {
                "Risk": [
                    "LOW RISK",
                    "MEDIUM RISK",
                    "HIGH RISK",
                ],
                "Scans": [
                    low,
                    medium,
                    high,
                ],
            }
        )

        st.bar_chart(
            chart_data.set_index("Risk"),
            use_container_width=True,
        )

        st.html(
            f"""
            <div style="
                margin-top:20px;
                padding:18px;

                border-radius:14px;

                background:rgba(10,17,29,0.70);
                border:1px solid rgba(90,140,220,0.12);

                color:#7e95b1;
                font-size:12px;
                line-height:1.6;
            ">
                <strong style="color:#dcecff;">
                    Current dataset:
                </strong>

                {total} URL scans.

                The current prototype calculates risk using structural
                URL indicators rather than a trained machine-learning model.
            </div>
            """
        )


# =========================================================
# ABOUT PAGE
# =========================================================

elif page == "ABOUT":

    render_section_title(
        "About GRIZZONE",
        "A cybersecurity-focused BCA project for structural URL threat analysis.",
    )

    c1, c2 = st.columns(2)

    with c1:

        st.html(
            """
            <div style="
                padding:23px;

                border-radius:16px;

                background:
                    linear-gradient(
                        145deg,
                        rgba(13,22,38,0.90),
                        rgba(8,13,24,0.90)
                    );

                border:1px solid rgba(80,160,240,0.14);
            ">

                <div style="
                    color:#65e5ff;
                    font-size:10px;
                    letter-spacing:2px;
                ">
                    PROJECT
                </div>

                <div style="
                    margin-top:8px;
                    color:#edf7ff;
                    font-size:22px;
                    font-weight:800;
                ">
                    GRIZZONE
                </div>

                <div style="
                    margin-top:13px;
                    color:#8096b1;
                    font-size:13px;
                    line-height:1.7;
                ">
                    GRIZZONE is a rule-based phishing URL risk
                    analysis application designed to identify
                    suspicious structural characteristics in URLs.
                </div>

            </div>
            """
        )

    with c2:

        st.html(
            """
            <div style="
                padding:23px;

                border-radius:16px;

                background:
                    linear-gradient(
                        145deg,
                        rgba(13,22,38,0.90),
                        rgba(8,13,24,0.90)
                    );

                border:1px solid rgba(120,90,255,0.14);
            ">

                <div style="
                    color:#9b8cff;
                    font-size:10px;
                    letter-spacing:2px;
                ">
                    TECHNOLOGY
                </div>

                <div style="
                    margin-top:14px;
                    color:#c7d8eb;
                    font-size:13px;
                    line-height:2;
                ">
                    Python<br>
                    Streamlit<br>
                    SQLite<br>
                    Pandas<br>
                    Rule-based Detection
                </div>

            </div>
            """
        )

    st.html(
        """
        <div style="
            margin-top:25px;
            padding:22px;

            border-radius:16px;

            background:rgba(10,17,29,0.72);
            border:1px solid rgba(90,140,220,0.12);
        ">

            <div style="
                color:#8da6c5;
                font-size:11px;
                letter-spacing:2px;
                margin-bottom:14px;
            ">
                DETECTION FEATURES
            </div>

            <div style="
                display:grid;
                grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
                gap:10px;

                color:#9eb1c8;
                font-size:12px;
            ">

                <div>• HTTPS inspection</div>
                <div>• URL length analysis</div>
                <div>• IP address detection</div>
                <div>• @ symbol detection</div>
                <div>• Suspicious keyword detection</div>
                <div>• Hyphen analysis</div>
                <div>• Subdomain analysis</div>
                <div>• Double-slash detection</div>

            </div>

        </div>
        """
    )

    st.html(
        """
        <div style="
            margin-top:20px;
            padding:18px 20px;

            border-radius:14px;

            background:rgba(255,191,95,0.035);
            border:1px solid rgba(255,191,95,0.12);

            color:#8f9fb2;
            font-size:12px;
            line-height:1.6;
        ">

            <strong style="color:#e7c27b;">
                Important:
            </strong>

            GRIZZONE is currently a rule-based prototype.
            Its risk classification should not be treated as proof that
            a URL is malicious or safe. A production version would require
            larger datasets, stronger validation, security controls,
            threat-intelligence integration and extensive testing.

        </div>
        """
    )


# =========================================================
# FOOTER
# =========================================================

st.html(
    """
    <div style="
        margin-top:55px;
        padding-top:18px;

        border-top:1px solid rgba(90,140,220,0.10);

        display:flex;
        justify-content:space-between;
        gap:20px;
        flex-wrap:wrap;

        color:#435875;
        font-size:9px;
        letter-spacing:1.5px;
    ">

        <div>
            GRIZZONE // URL THREAT ANALYSIS
        </div>

        <div>
            RULE ENGINE ONLINE
        </div>

    </div>
    """
)