import streamlit as st
import pandas as pd
import html
import json
from database import create_database, register_user, authenticate_user, save_scan, get_scans
from detector import analyze_url
from intelligence import inspect_domain

st.set_page_config(page_title="GRIZZONE | URL Intelligence", page_icon="◈", layout="wide")
create_database()
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
html,body,[data-testid="stAppViewContainer"],.stApp{background:radial-gradient(ellipse at 50% -20%,#49327a44,transparent 52%),#07070b!important;color:#f3f2ff!important;font-family:Manrope,sans-serif}
.block-container{max-width:1220px;padding-top:1.5rem;padding-bottom:4rem}[data-testid="stHeader"]{background:transparent}#MainMenu,footer{visibility:hidden}
p,label{color:#c4c2d8}.stTextInput input{background:#0b0b12!important;color:#f7f5ff!important;border:1px solid #292638!important;border-radius:12px!important}
.stButton>button,.stFormSubmitButton>button{border-radius:12px;border:1px solid #6f61bd;background:linear-gradient(110deg,#8a75ff,#5b8dff);color:white;font-weight:800;min-height:44px}
.stButton>button:hover,.stFormSubmitButton>button:hover{box-shadow:0 8px 28px #7766ff33}
div[data-testid="stMetric"]{background:linear-gradient(145deg,#13131d,#0c0c12);border:1px solid #9690ff25;border-radius:16px;padding:16px}
hr{border-color:#262333!important}.brand{font-size:21px;letter-spacing:.25em;font-weight:800}.eyebrow{font:11px 'DM Mono',monospace;letter-spacing:.2em;color:#a99cff;text-transform:uppercase}
.hero{padding:40px 32px;border:1px solid #9690ff2e;border-radius:24px;background:radial-gradient(ellipse at 85% 0%,#3c2c7655,transparent 45%),linear-gradient(145deg,#13121d,#09090f);margin:20px 0}
.hero h1{font-size:clamp(36px,5vw,62px);line-height:1.03;margin:12px 0;color:#f7f5ff}.hero p{max-width:660px;color:#aaa8c2;line-height:1.8}
.panel{background:linear-gradient(145deg,#13131c,#0d0d13);border:1px solid #9690ff25;border-radius:18px;padding:22px;margin:10px 0}
.tag{display:inline-block;padding:6px 10px;border:1px solid #8171db55;background:#8d7bff12;color:#c4bbff;border-radius:999px;font:10px 'DM Mono',monospace}
.muted{font-size:12px;color:#9695ad}.result-title{font-size:26px;font-weight:800}
@keyframes drift{0%,100%{transform:translateY(0)}50%{transform:translateY(-7px)}}.core{font-size:58px;filter:drop-shadow(0 0 24px #8574ff77);animation:drift 5s ease-in-out infinite}
</style>""",unsafe_allow_html=True)

def header():
    a,b=st.columns([1.4,2])
    with a: st.markdown('<div class="brand">◈ GRIZZONE</div><div class="eyebrow">Website intelligence system</div>',unsafe_allow_html=True)
    with b:
        if st.session_state.get("user"):
            x,y=st.columns([3,1])
            with x: st.caption("SIGNED IN · "+st.session_state.user["email"])
            with y:
                if st.button("Log out",use_container_width=True):
                    st.session_state.clear(); st.rerun()
    st.divider()

def auth_screen():
    header()
    left,right=st.columns([1.1,1],gap="large")
    with left:
        st.markdown('<div class="hero"><div class="eyebrow">See beyond the surface</div><div class="core">◈</div><h1>Every link<br>has a story.</h1><p>Inspect the signals behind a URL — structure, domain records, TLS, reputation context, and the reasons a scan raises concern.</p><span class="tag">DARK AESTHETIC · CLEAR EVIDENCE</span></div>',unsafe_allow_html=True)
        st.caption("Anime-inspired visual direction. A low-risk result is not a guarantee that a site is safe.")
    with right:
        st.markdown('<div class="panel">',unsafe_allow_html=True)
        mode=st.radio("ACCOUNT",["Sign in","Create account"],horizontal=True,label_visibility="collapsed")
        with st.form("auth_form"):
            email=st.text_input("Email address",placeholder="you@example.com").strip().lower()
            password=st.text_input("Password",type="password",placeholder="At least 10 characters")
            confirm=st.text_input("Confirm password",type="password") if mode=="Create account" else ""
            submitted=st.form_submit_button("Continue →",use_container_width=True)
        if submitted:
            if mode=="Create account":
                if password!=confirm: st.error("Passwords do not match.")
                elif len(password)<10: st.error("Use at least 10 characters for your password.")
                else:
                    ok,msg=register_user(email,password)
                    st.success(msg+" Sign in to continue.") if ok else st.error(msg)
            else:
                user=authenticate_user(email,password)
                if user: st.session_state.user=user; st.rerun()
                else: st.error("Sign-in failed. Check your email and password.")
        st.markdown('</div>',unsafe_allow_html=True)
        st.markdown('<div class="muted">Passwords are stored as salted PBKDF2 hashes. Public deployment still needs HTTPS, secure hosting, persistent database storage, rate limiting, and account recovery.</div>',unsafe_allow_html=True)

def _markdown_dossier(scan):
    intel=scan.get("intelligence",{})
    profile=intel.get("site_profile",{})
    lines=[
        "# GRIZZONE — URL Intelligence Dossier",
        "",
        "## Submitted URL",
        scan.get("url","Not available"),
        "",
        "## Risk assessment",
        f"- Verdict: {scan.get('risk','Not available')}",
        f"- Heuristic score: {scan.get('score','Not available')}/100",
        "- Important: this score is a rule-based signal, not a probability or guarantee.",
        "",
        "## Why this verdict",
    ]
    lines.extend(["- "+str(reason) for reason in scan.get("reasons",[])] or ["- No suspicious structural indicators were returned."])
    lines += ["", "## Website identity and company profile"]
    for key,label in [
        ("domain","Domain"),("title","Page title"),("description","Description"),
        ("organization","Organization / company"),("legal_name","Legal name"),
        ("founder","Founder"),("founding_date","Founding date"),
        ("published_website","Website listed in metadata"),("canonical_url","Canonical URL"),
        ("language","Page language"),("generator","CMS / generator metadata"),
        ("robots_policy","Robots policy"),("theme_color","Theme color"),
        ("http_status","HTTP status"),("content_type","Content type"),
        ("server_header","Server header"),("last_modified","Last-Modified header"),
    ]:
        value=profile.get(key, intel.get(key, "Not found"))
        lines.append(f"- {label}: {value}")
    lines += ["", "### Related and official links"]
    lines.extend(["- "+str(x) for x in profile.get("official_links",[])] or ["- Not found"])
    lines += ["", "### Important page and resource links"]
    lines.extend([f"- {x.get('type','Link')}: {x.get('url','')}" for x in profile.get("important_pages",[])] or ["- Not found"])
    lines += ["", "### Social / author metadata"]
    lines.extend(["- "+str(x) for x in profile.get("social_profiles",[])] or ["- Not found"])
    research=intel.get("web_research",{})
    lines += ["", "## Public web research", "- Status: "+str(research.get("status","Not available"))]
    if research.get("answer"):
        lines += ["", str(research.get("answer"))]
    for item in research.get("results",[]):
        lines.append(f"- {item.get('title','Untitled')} — {item.get('url','')}")
        if item.get("snippet"):
            lines.append("  "+str(item.get("snippet")))
    lines += ["", "## Domain registration"]
    for key,label in [
        ("registrar","Registrar"),("registrant_contact","Public registrant/administrative contact"),
        ("created","Registration date"),("updated","Last updated"),("expires","Expiration"),
        ("domain_status","Domain status"),("nameservers","Nameservers"),
    ]:
        lines.append(f"- {label}: {intel.get(key,'Not disclosed')}")
    lines += ["", "## DNS records"]
    for kind,values in intel.get("dns_records",{}).items():
        lines.append(f"### {kind}")
        lines.extend(["- "+str(v) for v in values])
    if not intel.get("dns_records"):
        lines.append("- No DNS records were returned.")
    lines += ["", "## TLS certificate"]
    lines.append("- Summary: "+str(intel.get("tls","Not checked")))
    for key,value in intel.get("tls_details",{}).items():
        lines.append(f"- {key.replace('_',' ').title()}: {value}")
    lines += ["", "## Certificate transparency"]
    ct=intel.get("certificate_transparency",{})
    lines.append("- Status: "+str(ct.get("status","Not available")))
    for cert in ct.get("certificates",[]):
        lines.append(f"- Issuer: {cert.get('issuer','Not disclosed')}; logged: {cert.get('logged_at','Not disclosed')}; names: {cert.get('names','')}")
    lines += ["", "## Website response security headers"]
    for key,value in profile.get("security_headers",{}).items():
        lines.append(f"- {key}: {value}")
    lines += ["", "## Threat reputation", str(intel.get("reputation","Not available"))]
    lines += ["", "## URL structural signals"]
    for key,value in scan.get("features",{}).items():
        lines.append(f"- {key.replace('_',' ').title()}: {value}")
    lines += ["", "## Collection notes and limitations"]
    lines.extend(["- "+str(note) for note in intel.get("notes",[])] or ["- Some sources may be unavailable or incomplete."])
    lines.append("- Company identity fields are based on publicly published site metadata and are not independent proof of ownership.")
    lines.append("- Missing information means it was not found in the checked sources; it does not prove the information does not exist.")
    return "\n".join(lines)


def render_report(scan):
    score,risk,reasons,features=scan["score"],scan["risk"],scan["reasons"],scan["features"]
    intel=scan.get("intelligence",{})
    profile=intel.get("site_profile",{})
    color={"HIGH RISK":"#ff6485","MEDIUM RISK":"#ffc56e","LOW RISK":"#75e6bd"}.get(risk,"#a99cff")
    st.markdown(f'<div class="panel" style="border-color:{color}66"><div class="eyebrow">Analysis complete · heuristic assessment</div><div class="result-title" style="color:{color}">{risk}</div><div style="word-break:break-all">{html.escape(scan["url"])}</div><p class="muted">Score reflects local rules, not a probability of compromise.</p><div style="font-size:36px;color:{color};font-weight:800">{score}<span style="font-size:12px"> / 100 RISK SCORE</span></div></div>',unsafe_allow_html=True)
    md_report=_markdown_dossier(scan)
    d1,d2=st.columns(2)
    with d1:
        st.download_button("Download full dossier (.md)",md_report,file_name="grizzone_url_dossier.md",mime="text/markdown",use_container_width=True)
    with d2:
        st.download_button("Download raw evidence (.json)",json.dumps(scan,indent=2,ensure_ascii=False,default=str),file_name="grizzone_url_evidence.json",mime="application/json",use_container_width=True)
    t1,t2,t3,t4=st.tabs(["Why this verdict","Website & company profile","Domain & infrastructure","URL signals"])
    with t1:
        st.markdown("#### Evidence and reasoning")
        if reasons:
            for reason in reasons: st.markdown("- "+reason)
        else:
            st.success("No suspicious structural indicators were detected by the current rules. This is not proof of safety.")
        st.info("A clean structural scan, domain age, or HTTPS alone cannot prove a site is safe.")
        st.markdown("#### Threat reputation")
        st.write(intel.get("reputation","Not available"))
        st.caption("Reputation coverage depends on external services and API configuration.")
    with t2:
        st.markdown("#### Identity and organization")
        if profile.get("status"): st.caption(profile["status"])
        fields=[
            ("title","Page title"),("description","Website description"),
            ("organization","Organization / company name"),("legal_name","Legal name"),
            ("founder","Founder"),("founding_date","Founding date"),
            ("published_website","Website listed in metadata"),("canonical_url","Canonical URL"),
            ("language","Page language"),("generator","CMS / generator metadata"),
            ("robots_policy","Robots policy"),("theme_color","Theme color"),
            ("http_status","HTTP status"),("content_type","Content type"),
            ("server_header","Server header"),("last_modified","Last modified"),
        ]
        for key,label in fields:
            value=profile.get(key,"Not found")
            st.text(f"{label}: {value}")
        links=profile.get("official_links",[])
        st.markdown("#### Related profiles / links published by the site")
        if links:
            for link in links: st.write(link)
        else:
            st.caption("No related profile links found in checked metadata.")
        st.markdown("#### Important pages and resources")
        pages=profile.get("important_pages",[])
        if pages:
            for item in pages: st.write(f'{item.get("type","Link")}: {item.get("url","")}')
        else:
            st.caption("No about/contact/legal/resource links were identified in the homepage HTML.")
        st.markdown("#### Social and author metadata")
        social=profile.get("social_profiles",[])
        st.write(social if social else "Not found in checked metadata")
        st.markdown("#### Structured data types")
        st.write(profile.get("structured_data_types",[]))
        st.markdown("#### Public company / founder web research")
        research=intel.get("web_research",{})
        st.caption(research.get("status","Web research not available"))
        if research.get("answer"):
            st.write(research["answer"])
        results=research.get("results",[])
        if results:
            for item in results:
                title=item.get("title","Search result")
                url=item.get("url","")
                st.markdown(f"**{title}**")
                if url: st.write(url)
                if item.get("snippet"): st.caption(item["snippet"])
        else:
            st.info("For cross-site company background and founder research, configure TAVILY_API_KEY in the environment. Website metadata alone cannot provide a complete biography.")
        st.warning("Company, founder, and social details are claims published by the website unless independently corroborated.")
    with t3:
        st.markdown("#### Domain registration")
        for key,label in [("domain","Domain"),("registrar","Registrar"),("registrant_contact","Public registrant/contact"),("created","Registered"),("updated","Last updated"),("expires","Expires"),("domain_status","Domain status"),("nameservers","Nameservers")]:
            if intel.get(key): st.text(f"{label}: {intel[key]}")
        st.markdown("#### DNS records")
        dns_records=intel.get("dns_records",{})
        if dns_records:
            for record_type,records in dns_records.items():
                with st.expander(f"{record_type} records ({len(records)})"):
                    for record in records: st.code(str(record),language=None)
        else:
            st.caption("No DNS records were returned by the public resolver.")
        st.markdown("#### Network and TLS")
        st.text("Public DNS addresses: "+str(intel.get("dns","Unavailable")))
        st.text("TLS: "+str(intel.get("tls","Not checked")))
        tls_details=intel.get("tls_details",{})
        if tls_details:
            for key,value in tls_details.items():
                st.text(f"{key.replace('_',' ').title()}: {value}")
        st.markdown("#### Certificate transparency")
        ct=intel.get("certificate_transparency",{})
        st.caption(ct.get("status","Unavailable"))
        for cert in ct.get("certificates",[]):
            st.markdown(f"- **Logged:** {cert.get('logged_at','Not disclosed')} · **Issuer:** {cert.get('issuer','Not disclosed')}")
            st.caption("Names: "+cert.get("names",""))
        st.markdown("#### Response security headers")
        headers=profile.get("security_headers",{})
        if headers:
            st.table([{"Header":key,"Status":value} for key,value in headers.items()])
        else:
            st.caption("Response headers were unavailable.")
        for note in intel.get("notes",[]): st.caption("• "+note)
    with t4:
        st.markdown("#### URL structural signals")
        items=[("URL length",features.get("url_length")),("HTTPS","Yes" if features.get("uses_https") else "No"),("Dots",features.get("dot_count")),("Hyphens",features.get("hyphen_count")),("@ symbol","Yes" if features.get("has_at_symbol") else "No"),("IP address","Yes" if features.get("uses_ip") else "No"),("Subdomains",features.get("subdomain_count")),("Suspicious keywords",len(features.get("suspicious_keywords",[])))]
        cols=st.columns(4)
        for i,(label,value) in enumerate(items): cols[i%4].metric(label,str(value))
        with st.expander("All extracted URL features"):
            st.json(features)

def dashboard():
    header()
    nav=st.radio("Navigation",["Scanner","Scan history","About"],horizontal=True,label_visibility="collapsed")
    if nav=="Scanner":
        st.markdown('<div class="hero"><div class="eyebrow">◈ Domain intelligence · threat signals</div><h1>See through<br>the URL.</h1><p>Look beyond the link. Combine explainable URL heuristics with available domain, DNS, TLS and threat-reputation context.</p><span class="tag">STRUCTURAL ANALYSIS</span> &nbsp; <span class="tag">DOMAIN CONTEXT</span> &nbsp; <span class="tag">EXPLAINABLE RESULTS</span></div>',unsafe_allow_html=True)
        with st.form("scan_form"):
            url=st.text_input("URL to inspect",placeholder="https://example.com/login")
            go=st.form_submit_button("⌕  Analyze URL",use_container_width=True)
        st.caption("GRIZZONE checks public domain services and reads limited static HTML metadata from the site's homepage. It does not run JavaScript or follow redirects.")
        if go:
            try:
                score,risk,reasons,features=analyze_url(url.strip())
                with st.spinner("Collecting domain intelligence…"): intel=inspect_domain(url.strip(),features)
                scan={"url":url.strip(),"score":score,"risk":risk,"reasons":reasons,"features":features,"intelligence":intel}
                save_scan(st.session_state.user["id"],scan); st.session_state.last_scan=scan
            except ValueError as e: st.error(str(e))
            except Exception: st.error("The scan could not be completed. Check the URL and try again.")
        if st.session_state.get("last_scan"): render_report(st.session_state.last_scan)
    elif nav=="Scan history":
        st.markdown('<div class="eyebrow">Your private workspace</div><h1>Scan history</h1><p class="muted">Only scans associated with your account are shown here.</p>',unsafe_allow_html=True)
        scans=get_scans(st.session_state.user["id"])
        if scans: st.dataframe(pd.DataFrame(scans,columns=["Scanned at","URL","Score","Verdict"]),use_container_width=True,hide_index=True)
        else: st.info("No scans yet. Run your first analysis from Scanner.")
    else:
        st.markdown('<div class="eyebrow">About the system</div><h1>Signals, not guesses.</h1>',unsafe_allow_html=True)
        c1,c2=st.columns(2)
        with c1: st.markdown('<div class="panel"><h3>What we inspect</h3><p>URL structure, suspicious patterns, domain registration data when available, DNS resolution and TLS metadata.</p></div>',unsafe_allow_html=True)
        with c2: st.markdown('<div class="panel"><h3>What we do not claim</h3><p>No scanner guarantees safety. Some records are unavailable and reputation services may need API keys.</p></div>',unsafe_allow_html=True)

if not st.session_state.get("user"): auth_screen()
else: dashboard()
