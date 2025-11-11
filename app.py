# app.py — SecuCheck (Complete Passive Exposure Intelligence)
# Requisitos: streamlit, requests, fpdf2, dnspython, beautifulsoup4, tldextract

import os
import re
import socket
import requests
import dns.resolver
import urllib.parse
import tldextract
from datetime import datetime
from fpdf import FPDF, HTMLMixin
from bs4 import BeautifulSoup
import streamlit as st
from time import sleep

# -----------------------
# Page / Config
# -----------------------
st.set_page_config(page_title="SecuCheck — Exposure Intelligence", page_icon="🔎", layout="wide")
st.title("🔎 SecuCheck — External Exposure & Intelligence (Passive)")
st.write("Passive discovery: DNS, subdomains, exposed emails, IPs, quick port handshakes, API probes, WAF/CDN detection. Non-intrusive only.")

# -----------------------
# Constants / signatures
# -----------------------
SEC_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare", "cf-"],
    "Akamai": ["akamai", "akamaiedge", "ghost"],
    "Imperva": ["incapsula", "x-iinfo"],
    "AWS CloudFront": ["cloudfront", "x-amz-cf-id"],
    "Fastly": ["fastly"],
    "Sucuri": ["x-sucuri-id", "sucuri"],
    "Azure Frontdoor": ["azurefd", "x-azure-ref"],
    "Google": ["gws", "google"],
    "F5 / BIG-IP": ["bigip", "x-waf-event"],
    "BunnyCDN": ["bunnycdn"],
    "StackPath": ["stackpath"],
    "Fortinet": ["fortiwaf"],
    "Barracuda": ["barra"]
}

COMMON_WEB_PORTS = [80, 443, 8080, 8443]
COMMON_API_PATHS = [
    "/api/", "/api/v1/", "/api/v2/", "/wp-json/", "/graphql", "/graphql/",
    "/admin", "/login", "/status", "/health", "/sitemap.xml", "/.well-known/security.txt",
    "/.well-known/openid-configuration", "/.well-known/jwks.json"
]

IPINFO_URL = "https://ipinfo.io/{ip}/json"  # public (rate limited)
CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
BUFFEROVER_URL = "https://dns.bufferover.run/dns?q=.{domain}"

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
MAILTO_REGEX = re.compile(r"mailto:([^\?\"'>]+)")

# -----------------------
# Utilities
# -----------------------
def normalize_url(domain: str) -> str:
    d = domain.strip()
    if not d:
        return ""
    if not d.startswith(("http://", "https://")):
        return "https://" + d
    return d

def safe_get(url: str, timeout: int = 10):
    try:
        return requests.get(url, timeout=timeout, allow_redirects=True)
    except Exception:
        return None

def dns_query(domain: str, qtype: str, lifetime: int = 6):
    try:
        answers = dns.resolver.resolve(domain, qtype, lifetime=lifetime)
        return [str(r).strip() for r in answers]
    except Exception:
        return []

def get_ips_from_dns(hostname: str) -> list:
    try:
        ai = socket.getaddrinfo(hostname, None)
        addrs = sorted({x[4][0] for x in ai})
        return addrs
    except Exception:
        return []

def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def check_tcp_port(ip: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

# -----------------------
# Cookie Analyzer
# -----------------------
def analyze_cookies(set_cookie_header: str) -> dict:
    """
    Analiza la cabecera Set-Cookie para detectar banderas de seguridad.
    """
    flags = {"Secure": "✅ Present", "HttpOnly": "✅ Present", "SameSite": "✅ Present"}
    header_lower = (set_cookie_header or "").lower()
    if "secure" not in header_lower:
        flags["Secure"] = "❌ Missing"
    if "httponly" not in header_lower:
        flags["HttpOnly"] = "❌ Missing"
    if "samesite" not in header_lower:
        flags["SameSite"] = "❌ Missing"
    return flags

# -----------------------
# Subdomains (passive)
# -----------------------
def discover_subdomains_crt(domain: str, pause: float = 0.2) -> list:
    out = set()
    try:
        url = CRTSH_URL.format(domain=domain)
        r = requests.get(url, timeout=8)
        if r.status_code == 200:
            try:
                data = r.json()
                for entry in data:
                    nv = entry.get("name_value", "")
                    for line in nv.split("\n"):
                        if domain in line:
                            out.add(line.strip().lstrip("*."))
            except Exception:
                pass
        sleep(pause)
    except Exception:
        pass
    return sorted(out)

def discover_subdomains_bufferover(domain: str) -> list:
    out = set()
    try:
        url = BUFFEROVER_URL.format(domain=domain)
        r = requests.get(url, timeout=8)
        if r.status_code == 200:
            j = r.json()
            # FDNS_A entries like "ip,sub.domain.com"
            for t in j.get("FDNS_A", []) + j.get("RDNS", []) + j.get("Results", []):
                try:
                    if isinstance(t, str) and "," in t:
                        candidate = t.split(",")[1].strip()
                        if domain in candidate:
                            out.add(candidate.lstrip("*."))
                    else:
                        if isinstance(t, str) and domain in t:
                            out.add(t.lstrip("*."))
                except Exception:
                    pass
    except Exception:
        pass
    return sorted(out)

def discover_subdomains(domain: str, limit:int=200) -> list:
    s = set()
    try:
        s.update(discover_subdomains_crt(domain))
    except Exception:
        pass
    try:
        s.update(discover_subdomains_bufferover(domain))
    except Exception:
        pass
    cleaned = [d.lower().strip().lstrip("*.") for d in s if domain in d]
    cleaned = sorted(set(cleaned))[:limit]
    return cleaned

# -----------------------
# Email discovery (passive)
# -----------------------
def extract_emails_from_html(html: str) -> list:
    if not html:
        return []
    emails = set(EMAIL_REGEX.findall(html))
    for m in MAILTO_REGEX.findall(html):
        if EMAIL_REGEX.match(m.strip()):
            emails.add(m.strip())
    # also use BeautifulSoup to find mailto hrefs
    try:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.lower().startswith("mailto:"):
                candidate = href.split("mailto:")[1].split("?")[0]
                if EMAIL_REGEX.match(candidate):
                    emails.add(candidate)
    except Exception:
        pass
    return sorted(emails)

def harvest_emails_from_hosts(hosts: list, max_pages_per_host: int = 4) -> dict:
    results = {}
    paths_to_try = ["/", "/contact", "/contacto", "/about", "/acerca", "/.well-known/security.txt", "/robots.txt"]
    for h in hosts:
        found = set()
        base = ("https://" + h) if not h.startswith(("http://","https://")) else h
        tried = 0
        try:
            r = safe_get(base)
            if r and r.status_code==200:
                found.update(extract_emails_from_html(r.text))
                tried += 1
        except Exception:
            pass
        for p in paths_to_try:
            if tried >= max_pages_per_host:
                break
            try:
                r = safe_get(urllib.parse.urljoin(base, p))
                if r and r.status_code == 200 and r.text:
                    found.update(extract_emails_from_html(r.text))
                    tried += 1
            except Exception:
                pass
        results[h] = sorted(found)
    return results

# -----------------------
# API endpoints probe (passive)
# -----------------------
def probe_api_paths(base_url: str, paths: list = COMMON_API_PATHS, timeout: float = 4.0) -> dict:
    results = {}
    for p in paths:
        url = urllib.parse.urljoin(base_url.rstrip("/"), p.lstrip("/"))
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True)
            info = {"status": r.status_code, "final_url": r.url}
            ct = r.headers.get("Content-Type", "")
            if "application/json" in ct:
                try:
                    data = r.json()
                    if isinstance(data, dict):
                        info["json_keys_sample"] = list(data.keys())[:8]
                except Exception:
                    pass
            if "text/html" in ct:
                info["snippet"] = r.text[:400].replace("\n", " ")
            results[p] = info
        except Exception as e:
            results[p] = {"error": str(e)}
    return results

# -----------------------
# WAF / CDN / tech detection
# -----------------------
def detect_waf_and_cdn(headers_raw: dict, domain: str) -> list:
    raw = " ".join([f"{k}:{v}" for k, v in headers_raw.items()]) if headers_raw else ""
    raw_l = raw.lower()
    found = []
    for name, sigs in WAF_SIGNATURES.items():
        for s in sigs:
            if s.lower() in raw_l:
                found.append(name)
                break
    if not found:
        try:
            cnames = dns_query(domain, "CNAME")
            for c in cnames:
                c_l = c.lower()
                if "cloudfront" in c_l:
                    found.append("AWS CloudFront (CNAME)")
                if "cloudflare" in c_l:
                    found.append("Cloudflare (CNAME)")
                if "akamaiedge" in c_l or "akamaicdn" in c_l or "akamaiedge.net" in c_l:
                    found.append("Akamai (CNAME)")
        except Exception:
            pass
    return found if found else ["❌ None detected"]

def detect_tech_stack_from_html(html: str) -> list:
    lower = (html or "").lower()
    stack = []
    hints = {
        "WordPress": ["wp-content", "wp-includes", "wordpress"],
        "Shopify": ["cdn.shopify.com", "x-shopify-stage"],
        "Wix": ["wixstatic", "wix.com", "wix"],
        "Squarespace": ["squarespace.com"],
        "React.js": ["react.production.min.js", "data-reactroot", "webpack"],
        "Next.js": ["_next/static"],
        "Laravel": ["laravel"],
        "Drupal": ["drupal"],
        "Joomla": ["joomla"],
        "Express/Node": ["express"]
    }
    for name, markers in hints.items():
        for m in markers:
            if m in lower:
                stack.append(name)
                break
    return stack if stack else ["❌ Unknown/Custom"]

# -----------------------
# ASN / IP info
# -----------------------
def get_asn_info(ip: str) -> dict:
    try:
        r = requests.get(IPINFO_URL.format(ip=ip), timeout=6)
        if r.status_code == 200:
            data = r.json()
            return {
                "ip": ip,
                "org": data.get("org"),
                "asn": (data.get("asn") if isinstance(data.get("asn"), str) else (data.get("asn", {}).get("asn") if isinstance(data.get("asn"), dict) else None)),
                "country": data.get("country"),
                "region": data.get("region"),
                "city": data.get("city")
            }
        else:
            return {"ip": ip, "error": f"ipinfo {r.status_code}"}
    except Exception as e:
        return {"ip": ip, "error": str(e)}

# -----------------------
# Shodan optional / Hunter optional
# -----------------------
def shodan_lookup(ip: str) -> dict:
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        return {"error": "No SHODAN_API_KEY configured"}
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
        r = requests.get(url, timeout=8)
        if r.status_code == 200:
            data = r.json()
            services = []
            for svc in data.get("data", [])[:12]:
                services.append({"port": svc.get("port"), "banner": svc.get("data", "")[:200]})
            return {"ip": ip, "org": data.get("org"), "country": data.get("country_name"), "services": services}
        else:
            return {"error": f"Shodan returned {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def hunter_lookup(domain: str) -> dict:
    key = os.environ.get("HUNTER_API_KEY")
    if not key:
        return {"error": "No HUNTER_API_KEY configured"}
    try:
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={key}"
        r = requests.get(url, timeout=8)
        if r.status_code == 200:
            return r.json()
        else:
            return {"error": f"Hunter returned {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# -----------------------
# Scoring + finance
# -----------------------
def calculate_score(headers: dict, tls_ok: bool, waf_cdn: list, cookies_flags: dict) -> tuple:
    score = 100
    missing_headers = [h for h in SEC_HEADERS if "Missing" in str(headers.get(h, ""))]
    score -= 10 * len(missing_headers)
    if waf_cdn == ["❌ None detected"]:
        score -= 15
    if not tls_ok:
        score -= 30
    for f in ["Secure", "HttpOnly", "SameSite"]:
        if cookies_flags.get(f) == "❌ Missing":
            score -= 5
    score = max(0, min(100, score))
    grade = "A" if score > 90 else "B" if score > 75 else "C" if score > 60 else "D" if score > 45 else "F"
    return grade, score, missing_headers

def financial_estimate(score: int, monthly_revenue: float = None) -> dict:
    if score >= 90:
        breach_prob = 0.02
    elif score >= 75:
        breach_prob = 0.05
    elif score >= 60:
        breach_prob = 0.12
    elif score >= 45:
        breach_prob = 0.25
    else:
        breach_prob = 0.45
    avg_cost = 250000
    if monthly_revenue and monthly_revenue > 0:
        annual_rev = monthly_revenue * 12
        capped_loss = min(avg_cost, 0.5 * annual_rev)
        expected_annual_loss = breach_prob * capped_loss
        return {"breach_probability": breach_prob, "expected_annual_loss_usd": expected_annual_loss, "annual_revenue_used": annual_rev}
    else:
        return {"breach_probability": breach_prob, "example_avg_cost_usd": avg_cost}

# -----------------------
# PDF (fpdf2)
# -----------------------
class PDF(FPDF, HTMLMixin):
    pass

def generate_pdf(domain: str,
                 exec_summary: dict,
                 headers: dict,
                 cookies_flags: dict,
                 dnsinfo: dict,
                 ips: dict,
                 ptrs: dict,
                 port_results: dict,
                 api_probes: dict,
                 waf_cdn: list,
                 tech_stack: list,
                 asn_data: list,
                 subdomains: list,
                 emails: dict,
                 shodan_results: dict,
                 hunter_results: dict,
                 grade: str,
                 score: int,
                 fin_est: dict,
                 recs: list) -> str:
    pdf = PDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=16)
    pdf.cell(0, 10, "SecuCheck — Exposure Intelligence Report", ln=True, align="C")
    pdf.ln(3)

    pdf.set_font("Helvetica", size=11)
    pdf.multi_cell(0, 6, f"Domain: {domain}")
    pdf.multi_cell(0, 6, f"Scan date (UTC): {datetime.utcnow().isoformat()}")
    pdf.multi_cell(0, 6, f"Grade: {grade} ({score}%)")
    pdf.multi_cell(0, 6, f"Executive summary: {exec_summary.get('exec','See details')}")
    pdf.ln(4)

    pdf.multi_cell(0, 7, "=== Key findings ===")
    for k, v in exec_summary.get("top", {}).items():
        pdf.multi_cell(0, 6, f"- {k}: {v}")
    pdf.ln(3)

    pdf.multi_cell(0, 7, "=== Subdomains discovered (sample) ===")
    if subdomains:
        for s in subdomains[:80]:
            pdf.multi_cell(0, 6, f"- {s}")
    else:
        pdf.multi_cell(0, 6, "No subdomains discovered via passive sources.")

    pdf.ln(2)
    pdf.multi_cell(0, 7, "=== Exposed emails found (sample) ===")
    for host, ems in emails.items():
        if ems:
            pdf.multi_cell(0,6, f"{host}: {', '.join(ems[:6])}")

    pdf.ln(2)
    pdf.multi_cell(0, 7, "=== Security headers ===")
    for h in SEC_HEADERS:
        pdf.multi_cell(0, 6, f"{h}: {headers.get(h, 'N/A')}")

    pdf.ln(2)
    pdf.multi_cell(0, 7, "=== Cookie flags ===")
    for k, v in cookies_flags.items():
        pdf.multi_cell(0, 6, f"{k}: {v}")

    pdf.ln(2)
    pdf.multi_cell(0, 7, "=== DNS sample ===")
    for t in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
        if dnsinfo.get(t):
            pdf.multi_cell(0, 6, f"{t}: {', '.join(dnsinfo.get(t))}")

    pdf.ln(2)
    pdf.multi_cell(0, 7, "=== IPs & PTR (sample) ===")
    if ips.get("A"): pdf.multi_cell(0,6, f"A: {', '.join(ips.get('A'))}")
    if ips.get("AAAA"): pdf.multi_cell(0,6, f"AAAA: {', '.join(ips.get('AAAA'))}")
    for ip, ptr in ptrs.items():
        pdf.multi_cell(0,6, f"PTR {ip}: {ptr}")

    pdf.ln(2)
    pdf.multi_cell(0, 7, "=== Quick port handshake results ===")
    for ip, pdata in port_results.items():
        pdf.multi_cell(0, 6, f"{ip}: " + ", ".join([f"{p}:{'Open' if s else 'Closed'}" for p, s in pdata.items()]))

    pdf.ln(2)
    pdf.multi_cell(0, 7, "=== API endpoints probed (sample) ===")
    for p, info in api_probes.items():
        try:
            if "status" in info:
                pdf.multi_cell(0,6, f"{p} -> {info.get('status')} ({info.get('final_url')})")
            else:
                pdf.multi_cell(0,6, f"{p} -> error: {info.get('error')}")
        except Exception:
            pass

    pdf.ln(2)
    pdf.multi_cell(0, 7, "=== CDN / WAF detections ===")
    pdf.multi_cell(0, 6, ", ".join(waf_cdn))

    pdf.ln(2)
    pdf.multi_cell(0, 7, "=== Tech stack hints ===")
    pdf.multi_cell(0, 6, ", ".join(tech_stack))

    pdf.ln(2)
    pdf.multi_cell(0, 7, "=== ASN / Provider info (sample) ===")
    for a in asn_data:
        pdf.multi_cell(0, 6, str(a))

    if shodan_results:
        pdf.ln(2)
        pdf.multi_cell(0, 7, "=== Shodan (optional) ===")
        for ip, v in shodan_results.items():
            pdf.multi_cell(0,6, f"{ip}: {str(v)[:200]}")

    if hunter_results:
        pdf.ln(2)
        pdf.multi_cell(0, 7, "=== Hunter (optional) ===")
        pdf.multi_cell(0,6, str(hunter_results)[:800])

    pdf.ln(3)
    pdf.multi_cell(0, 7, "=== Recommendations ===")
    for r in recs:
        pdf.multi_cell(0, 6, f"- {r}")

    pdf.ln(3)
    pdf.multi_cell(0, 7, "=== Financial risk estimate ===")
    for k, v in fin_est.items():
        pdf.multi_cell(0, 6, f"{k}: {v}")

    fname = f"{domain.replace('https://','').replace('http://','').strip('/')}_exposure_report.pdf"
    pdf.output(fname)
    return fname

# -----------------------
# Recommendations builder
# -----------------------
def build_recommendations(missing_headers: list, waf_cdn: list, cookies_flags: dict, tls_ok: bool, exposure: list) -> list:
    recs = []
    if missing_headers:
        recs.append(f"Implement missing security headers: {', '.join(missing_headers)} (CSP, HSTS w/ preload, X-Frame-Options, Referrer-Policy).")
    if waf_cdn == ["❌ None detected"]:
        recs.append("Deploy a Web Application Firewall (WAF) such as Cloudflare WAF to protect Layer 7.")
    if not tls_ok:
        recs.append("Enable HTTPS and configure HSTS with includeSubDomains and preload.")
    if cookies_flags.get("Secure") == "❌ Missing" or cookies_flags.get("HttpOnly") == "❌ Missing":
        recs.append("Harden cookies: set Secure; HttpOnly; SameSite=Strict for session cookies.")
    if exposure:
        recs.append("Remove or neutralize Server and X-Powered-By headers; normalize responses via CDN/proxy.")
    recs.append("Consider an authorized PoC deep scan and remediation engagement to quantify and fix exposure.")
    return recs

# -----------------------
# UI and main flow
# -----------------------
with st.form("exposure_form"):
    domain_input = st.text_input("Domain (example.com):", value="", placeholder="example.com")
    monthly_rev = st.number_input("Optional: Monthly revenue (USD) to estimate financial impact", min_value=0.0, value=0.0, step=100.0)
    probe_ports_toggle = st.checkbox("Run quick port handshake on common web ports (safe, minimal)", value=True)
    shodan_toggle = st.checkbox("Include Shodan lookup (requires SHODAN_API_KEY env var)", value=False)
    hunter_toggle = st.checkbox("Include Hunter.io domain email lookup (requires HUNTER_API_KEY env var)", value=False)
    scan_subdomains_toggle = st.checkbox("Include passive subdomain discovery (crt.sh, bufferover)", value=True)
    submit = st.form_submit_button("Run Exposure Intelligence Scan")

if submit:
    if not domain_input.strip():
        st.warning("Please enter a domain.")
    else:
        target = normalize_url(domain_input)
        st.info("Running passive checks. This will query public services only (non-intrusive).")

        # HTTP fetch
        r = safe_get(target)
        headers = {}
        html_sample = ""
        tls_ok = False
        if r:
            headers = {h: r.headers.get(h, "❌ Missing") for h in SEC_HEADERS}
            headers["Status Code"] = r.status_code
            headers["Final URL"] = r.url
            headers["Server"] = r.headers.get("Server", r.headers.get("server", "Unknown"))
            headers["_raw_headers"] = {k.lower(): v for k, v in r.headers.items()}
            headers["_set_cookie"] = r.headers.get("Set-Cookie", "")
            tls_ok = True if r.url.startswith("https://") else False
            try:
                html_sample = r.text[:4000]
            except Exception:
                html_sample = ""
        else:
            st.error("HTTP fetch failed or timed out — continuing with DNS/Resolution checks.")
            headers = {h: "❌ Not fetched" for h in SEC_HEADERS}
            headers["_raw_headers"] = {}
            headers["_set_cookie"] = ""
            headers["Status Code"] = "N/A"
            headers["Final URL"] = "N/A"

        # DNS & IPs
        hostname = urllib.parse.urlparse(target).hostname
        dnsinfo = {}
        for rec in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
            dnsinfo[rec] = dns_query(hostname, rec)
        ips_list = get_ips_from_dns(hostname)
        ptrs = {ip: reverse_dns(ip) for ip in ips_list}

        # Subdomains
        subdomains = []
        if scan_subdomains_toggle:
            try:
                subdomains = discover_subdomains(hostname)
            except Exception:
                subdomains = []

        # Harvest emails (root + discovered subdomains sample)
        email_hosts = [hostname]
        if subdomains:
            email_hosts += subdomains[:20]
        emails_found = harvest_emails_from_hosts(email_hosts, max_pages_per_host=3)

        # Ports
        port_results = {}
        if probe_ports_toggle and ips_list:
            for ip in ips_list:
                port_results[ip] = {}
                for p in COMMON_WEB_PORTS:
                    port_results[ip][p] = check_tcp_port(ip, p)

        # API probes
        api_probes = probe_api_paths(target)

        # WAF/CDN & tech stack
        waf_cdn = detect_waf_and_cdn(headers.get("_raw_headers", {}), hostname)
        tech_stack = detect_tech_stack_from_html(html_sample)

        # ASN info sample
        asn_data = []
        for ip in ips_list[:2]:
            asn_data.append(get_asn_info(ip))

        # Shodan optional
        shodan_results = {}
        if shodan_toggle:
            for ip in ips_list[:2]:
                shodan_results[ip] = shodan_lookup(ip)

        # Hunter optional
        hunter_results = {}
        if hunter_toggle:
            hunter_results = hunter_lookup(hostname)

        # cookies & scoring
        cookies_flags = analyze_cookies(headers.get("_set_cookie", ""))
        grade, score, missing_headers = calculate_score(headers, tls_ok, waf_cdn, cookies_flags)
        fin_est = financial_estimate(score, monthly_rev if monthly_rev > 0 else None)
        recs = build_recommendations(missing_headers, waf_cdn, cookies_flags, tls_ok, tech_stack if tech_stack and tech_stack[0] != "❌ Unknown/Custom" else [])

        # executive summary
        exec_summary = {
            "exec": f"Passive external audit for {hostname}. Grade {grade} ({score}%). Key issues: {', '.join(missing_headers) or 'none critical'}. WAF: {', '.join(waf_cdn)}. Found {sum(len(v) for v in emails_found.values())} exposed email(s) in public pages / contact files.",
            "top": {
                "Grade": f"{grade} ({score}%)",
                "Missing headers": ", ".join(missing_headers) if missing_headers else "None",
                "WAF/CDN": ", ".join(waf_cdn),
                "Emails found (sample)": ", ".join(next((v for v in emails_found.values() if v), ["None"])) 
            }
        }

        # UI output
        st.success("Scan complete ✅")
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Security Grade", f"{grade}", f"{score}%")
        with c2:
            st.metric("WAF/CDN", ", ".join(waf_cdn))
        with c3:
            st.metric("TLS/HTTPS", "✅" if tls_ok else "❌")

        with st.expander("Executive summary (copyable)"):
            st.write(exec_summary["exec"])
            st.json(exec_summary["top"])

        with st.expander("Subdomains discovered (sample)"):
            st.json(subdomains[:200])

        with st.expander("Exposed emails (sample)"):
            st.json({k: v for k, v in emails_found.items() if v})

        with st.expander("Security headers"):
            st.json({k: headers.get(k) for k in SEC_HEADERS})

        with st.expander("Cookies flags"):
            st.json(cookies_flags)

        with st.expander("DNS info"):
            st.json(dnsinfo)

        with st.expander("Resolved IPs & PTR"):
            st.json({"ips": ips_list, "ptrs": ptrs})

        if probe_ports_toggle:
            with st.expander("Quick port handshake results"):
                st.json(port_results)

        with st.expander("API endpoints probed (sample)"):
            st.json(api_probes)

        with st.expander("Tech stack hints & CDN/WAF"):
            st.json({"tech_stack": tech_stack, "waf_cdn": waf_cdn, "shodan_optional": shodan_results, "hunter_optional": hunter_results})

        with st.expander("ASN / provider info (sample)"):
            st.json(asn_data)

        with st.expander("Recommendations"):
            for r in recs:
                st.markdown(f"- {r}")

        # generate PDF and download
        pdf_path = generate_pdf(
            domain=hostname,
            exec_summary=exec_summary,
            headers=headers,
            cookies_flags=cookies_flags,
            dnsinfo=dnsinfo,
            ips={"A": [i for i in ips_list if ":" not in i], "AAAA": [i for i in ips_list if ":" in i]},
            ptrs=ptrs,
            port_results=port_results,
            api_probes=api_probes,
            waf_cdn=waf_cdn,
            tech_stack=tech_stack,
            asn_data=asn_data,
            subdomains=subdomains,
            emails=emails_found,
            shodan_results=shodan_results,
            hunter_results=hunter_results,
            grade=grade,
            score=score,
            fin_est=fin_est,
            recs=recs
        )
        try:
            with open(pdf_path, "rb") as f:
                st.download_button("📄 Download Exposure PDF", data=f, file_name=pdf_path, mime="application/pdf")
        except Exception as e:
            st.error(f"Error creating PDF: {e}")

        st.caption("Passive external discovery only. No intrusive scanning or exploitation performed. For deep authorized scans & remediation contact us for a PoC.")

# EOF
