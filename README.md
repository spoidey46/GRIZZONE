# GRIZZONE — URL Intelligence

A dark, anime-inspired Streamlit application for explainable URL-risk analysis. The current feature branch adds user registration/login, per-account scan history, passive domain intelligence, and an optional VirusTotal lookup.

## Run locally

Requires Python 3.10 or newer.

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

Open the local URL printed by Streamlit (usually http://localhost:8501). Create an account in the app, then sign in and scan a URL.

## Optional VirusTotal integration

Set your VirusTotal API key in your local environment. Do not paste keys into source files or commit them to GitHub.

Windows PowerShell (current terminal only):

```powershell
$env:VT_API_KEY = "your-key-here"
streamlit run app.py
```

If no key is configured, VirusTotal reputation is explicitly shown as not configured. RDAP and DNS/TLS lookups may fail due to network restrictions, unavailable records, or rate limits.

## Current limitations and safety notes

- The score is a heuristic risk indicator, not a probability that a URL is malicious.
- A low-risk result does not guarantee safety; reputation and domain history can be incomplete.
- GRIZZONE does not fetch or render the submitted page. Domain metadata lookups contact public services.
- Accounts use salted PBKDF2-HMAC-SHA256 password hashes. The demo does not yet provide email verification, password reset, account lockout/rate limiting, or production-grade session management.
- The default SQLite database is local. For public hosting, use a persistent database, HTTPS, secure secret management, request throttling, robust authorization review, and deployment-specific hardening.
- Legacy scans created before user accounts were added remain unassigned and are not shown in user-specific history.

## Feature branch

This upgrade is being developed on `feature/grizzone-intelligence-ui-auth`; `main` is not changed by these commits.
