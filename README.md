# GRIZZONE — URL Intelligence

A dark, anime-inspired Streamlit application for explainable URL-risk analysis. The feature branch adds user registration/login, per-account scan history, a downloadable URL intelligence dossier (Markdown and JSON), website/company metadata, RDAP domain records, DNS record lookups, TLS details, certificate-transparency samples, HTTP security-header checks, and optional VirusTotal reputation and public web research.

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

## Optional public web research

To include search results about the company/founder from public webpages, configure a Tavily API key in your local environment. The search feature is optional; the rest of the scanner works without it. Do not paste API keys into source files or commit them to GitHub.

Windows PowerShell (current terminal only):

```powershell
$env:TAVILY_API_KEY = "your-key-here"
streamlit run app.py
```

When configured, GRIZZONE searches for what the organization does, its products and services, target customers, founders, and company history. It displays a summary and source links in the website/company profile and downloadable dossier. Search snippets can be incomplete or incorrect, so open the source links and verify claims. This is not a guarantee of a complete biography.

## Current limitations and safety notes

- The score is a heuristic risk indicator, not a probability that a URL is malicious.
- A low-risk result does not guarantee safety; reputation and domain history can be incomplete.
- GRIZZONE reads a limited amount of static HTML from the site's homepage to extract title, description, canonical URL, language, generator hints, structured organization/person details, social metadata, and likely about/contact/legal links. It does not execute JavaScript or follow redirects. Public lookups include RDAP, DNS-over-HTTPS, and certificate-transparency records; network access or rate limits may make some sources unavailable.
- The report includes available DNS A/AAAA/MX/NS/TXT/CAA/SOA records, TLS certificate metadata, sampled certificate-transparency entries, and selected HTTP security headers. These signals describe public infrastructure and are not proof that a company or website is legitimate.
- Use the Markdown dossier for a readable report or JSON to preserve the full collected evidence from a scan.
- Company name, legal name, founder, and founding date are displayed only when found in parseable public metadata. These are website claims, not independently verified ownership facts; missing information is shown as unavailable. A complete biography cannot be guaranteed from a URL alone.
- Accounts use salted PBKDF2-HMAC-SHA256 password hashes. The demo does not yet provide email verification, password reset, account lockout/rate limiting, or production-grade session management.
- The default SQLite database is local. For public hosting, use a persistent database, HTTPS, secure secret management, request throttling, robust authorization review, and deployment-specific hardening.
- Legacy scans created before user accounts were added remain unassigned and are not shown in user-specific history.

## Feature branch

This upgrade is being developed on `feature/grizzone-intelligence-ui-auth`; `main` is not changed by these commits.
