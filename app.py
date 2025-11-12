# app.py — SecuCheck demo v2 (no PDF, traffic sim + expanded ports + proxy/worker relay)
# Requirements (requirements.txt):
# streamlit
# requests
# fpdf2
# dnspython
# beautifulsoup4
# tldextract

import os
import re
import socket
import requests
import dns.resolver
import urllib.parse
import tldextract
from datetime import datetime
from bs4 import BeautifulSoup
import streamlit as st
from time import sleep, time

st.set_page_config(page_title="SecuCheck — Demo (Traffic + Exposure)", layout="wide")
st.title("🔎 SecuCheck — Exposure + Safe Traffic Demo")
st.write("Herramienta passive + demo controlada de tráfico (solo con permiso). Usa proxy/worker si no quieres exponer tu IP.")

# --------- Config / Signatures ----------
SEC_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare", "cf-"],
    "Akamai": ["akamai", "akamaiedge"],
    "Imperva": ["incapsula", "x-iinfo"],
    "AWS CloudFront": ["cloudfront", "x-amz-cf-id"],
    "Fastly": ["fastly"],
    "Sucuri": ["x-sucuri-id", "sucuri"],
    "Azure Frontdoor": ["azurefd", "x-azure-ref"],
    "Google": ["gws"],
    "F5 / BIG-IP": ["bigip"],
}

# ampliamos puertos (20) — solo handshake TCP (no payload)
COMMON_PORTS = [21,22,23,25,53,80,110,135,139,143,161,443,445,465,587,993,995,1433,3306,3389,8080,8443]

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
BUFFEROVER_URL = "https://dns.bufferover.run/dns?q=.{domain}"
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
MAILTO_REGEX = re.compile(r"mailto:([^\?\"'>]+)")

# --------- Utils ----------
def normalize_url(domain: str) -> str:
    d = domain.strip()
    if not d:
        return ""
    if not d.startswith(("http://", "https://")):
        return "https://" + d
    return d

def safe_get(url: str, timeout: int = 8, headers=None, proxies=None):
    try:
        return requests.get(url, timeout=timeout, allow_redirects=True, headers=headers or {}, proxies=proxies)
    except Exception:
        return None

def dns_query(domain: str, qtype: str, lifetime: int = 6):
    try:
        return [str(r).strip() for r in dns.resolver.resolve(domain, qtype, lifetime=lifetime)]
    except Exception:
        return []

def get_ips(hostname: str) -> list:
    try:
        ai = socket.getaddrinfo(hostname, None)
        return sorted({x[4][0] for x in ai})
    except Exception:
        return []

def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def check_tcp(ip: str, port: int, timeout: float = 0.6) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

# cookie analyzer
def analyze_cookies(set_cookie_header: str) -> dict:
    flags = {"Secure": "✅ Present", "HttpOnly": "✅ Present", "SameSite": "✅ Present"}
    header_lower = (set_cookie_header or "").lower()
    if "secure" not in header_lower:
        flags["Secure"] = "❌ Missing"
    if "httponly" not in header_lower:
        flags["HttpOnly"] = "❌ Missing"
    if "samesite" not in header_lower:
        flags["SameSite"] = "❌ Missing"
    return flags

# subdomain passive discovery
def discover_crt(domain: str):
    out = set()
    try:
        r = requests.get(CRTSH_URL.format(domain=domain), timeout=8)
        if r.status_code == 200:
            data = r.json()
            for e in data:
                nv = e.get("name_value","")
                for line in nv.split("\n"):
                    if domain in line:
                        out.add(line.strip().lstrip("*."))
    except Exception:
        pass
    return sorted(out)

def discover_bufferover(domain: str):
    out = set()
    try:
        r = requests.get(BUFFEROVER_URL.format(domain=domain), timeout=8)
        if r.status_code == 200:
            j = r.json()
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

def discover_subdomains(domain: str, limit=200):
    s = set()
    s.update(discover_crt(domain))
    s.update(discover_bufferover(domain))
    cleaned = [d.lower().strip().lstrip("*.") for d in s if domain in d]
    return sorted(set(cleaned))[:limit]

# email harvest (passive)
def extract_emails(html: str):
    if not html:
        return []
    emails = set(EMAIL_REGEX.findall(html))
    for m in MAILTO_REGEX.findall(html):
        if EMAIL_REGEX.match(m.strip()):
            emails.add(m.strip())
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

def harvest_emails(hosts:list, max_pages=3):
    results = {}
    paths = ["/", "/contact", "/contacto", "/about", "/.well-known/security.txt", "/robots.txt"]
    for h in hosts:
        base = ("https://" + h) if not h.startswith(("http","https")) else h
        found = set()
        try:
            r = safe_get(base)
            if r and r.status_code==200:
                found.update(extract_emails(r.text))
        except Exception:
            pass
        tries = 0
        for p in paths:
            if tries >= max_pages: break
            try:
                r = safe_get(urllib.parse.urljoin(base,p))
                if r and r.status_code==200:
                    found.update(extract_emails(r.text))
                    tries += 1
            except Exception:
                pass
        results[h] = sorted(found)
    return results

# detect waf/cdn
def detect_waf(headers:dict, domain:str):
    raw = " ".join([f"{k}:{v}" for k,v in headers.items()]) if headers else ""
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
                if "cloudfront" in c_l: found.append("AWS CloudFront (CNAME)")
                if "cloudflare" in c_l: found.append("Cloudflare (CNAME)")
                if "akamai" in c_l: found.append("Akamai (CNAME)")
        except Exception:
            pass
    return found if found else ["❌ None detected"]

# quick API probe
COMMON_API_PATHS = ["/api/","/api/v1/","/api/v2/","/wp-json/","/graphql","/health","/status","/.well-known/security.txt"]
def probe_apis(base:str, headers=None, proxies=None):
    out = {}
    for p in COMMON_API_PATHS:
        try:
            url = urllib.parse.urljoin(base.rstrip("/"), p.lstrip("/"))
            r = requests.get(url, timeout=5, allow_redirects=True, headers=headers or {}, proxies=proxies)
            info = {"status": r.status_code, "final_url": r.url}
            ct = r.headers.get("Content-Type","")
            if "application/json" in ct:
                try:
                    j = r.json()
                    if isinstance(j, dict):
                        info["json_keys_sample"] = list(j.keys())[:8]
                except Exception:
                    pass
            if "text/html" in ct:
                info["snippet"] = r.text[:300].replace("\n"," ")
            out[p] = info
        except Exception as e:
            out[p] = {"error": str(e)}
    return out

# --------- Traffic simulation helpers ----------
def build_proxies_from_env():
    # SAFE_PROXY must be like "http://user:pass@host:port" or "http://host:port"
    proxy = os.environ.get("SAFE_PROXY")
    if not proxy:
        return None
    return {"http": proxy, "https": proxy}

def worker_relay_request(worker_url: str, target_url: str, headers=None, timeout=8):
    """
    If you have a Cloudflare Worker that forwards requests to target, call it like:
    GET {WORKER_URL}?target=https://example.com/path
    Worker should perform request and return status & headers/body snippet.
    This keeps your IP hidden (Worker makes the outbound call).
    """
    try:
        payload = {"target": target_url}
        r = requests.get(worker_url, params=payload, timeout=timeout, headers=headers or {})
        if r and r.status_code == 200:
            return {"status": r.status_code, "final_url": r.url, "body_snippet": r.text[:400]}
        else:
            return {"status": r.status_code if r else "noresp", "error": "worker_error"}
    except Exception as e:
        return {"error": str(e)}

def simulate_traffic(domain, path="/robots.txt", num_requests=30, delay=0.4, use_worker=None, proxies=None, user_agent=None):
    """
    Simula requests ligeras y controladas a una ruta segura (robots.txt por defecto).
    - use_worker: si pones URL de worker, las requests van por él.
    - proxies: dict para requests (SAFE_PROXY)
    Devuelve conteo y tiempos.
    """
    stats = {"sent":0, "200":0, "other":0, "errors":0, "details":[]}
    headers = {"User-Agent": user_agent or "SecuCheck-Demo/1.0 (+https://theclouddefender.example)"}
    target_base = domain.strip()
    if not target_base.startswith(("http://","https://")):
        target_base = "https://" + target_base
    for i in range(max(1, int(num_requests))):
        url = urllib.parse.urljoin(target_base, path)
        try:
            if use_worker:
                res = worker_relay_request(use_worker, url, headers=headers)
                if res.get("status")==200:
                    stats["200"] += 1
                elif "error" in res:
                    stats["errors"] += 1
                else:
                    stats["other"] += 1
                stats["details"].append(res)
            else:
                r = requests.get(url, timeout=6, headers=headers, proxies=proxies)
                stats["sent"] += 1
                if r.status_code == 200:
                    stats["200"] += 1
                else:
                    stats["other"] += 1
                stats["details"].append({"status": r.status_code, "url": r.url})
        except Exception as e:
            stats["errors"] += 1
            stats["details"].append({"error": str(e)})
        sleep(max(0, float(delay)))
    return stats

# --------- UI ----------
with st.form("form"):
    domain = st.text_input("Domain (example.com):", value="", placeholder="example.com")
    st.markdown("**Passive checks** (headers, DNS, subdomains, emails, IPs, quick port handshakes).")
    run_ports = st.checkbox("Run quick port handshake on expanded ports (safe, minimal)", value=True)
    run_subdomains = st.checkbox("Include passive subdomain discovery (crt.sh, bufferover)", value=True)
    show_shodan = st.checkbox("Include Shodan lookup (requires SHODAN_API_KEY env)", value=False)
    st.markdown("---")
    st.markdown("**Traffic demo (only with permission)**")
    do_simulate = st.checkbox("Enable controlled traffic simulation (must have permission)", value=False)
    sim_requests = st.number_input("Requests to send (demo)", min_value=1, max_value=200, value=30)
    sim_delay = st.number_input("Delay between requests (seconds)", min_value=0.0, max_value=5.0, value=0.4, step=0.1)
    sim_path = st.text_input("Path to request (safe path)", value="/robots.txt")
    use_worker_checkbox = st.checkbox("Route simulation through Cloudflare Worker (recommended to hide IP)", value=False)
    use_worker_url = st.text_input("WORKER URL (if using)", value=os.environ.get("WORKER_URL",""))
    use_proxy_checkbox = st.checkbox("Route simulation through SAFE_PROXY (optional)", value=False)
    st.markdown("**Note:** Either worker or SAFE_PROXY is recommended if you don't want your IP logged. Configure SAFE_PROXY env or WORKER_URL.")
    submit = st.form_submit_button("Run scan")

if submit:
    if not domain.strip():
        st.error("Please enter a domain.")
    else:
        hostname = urllib.parse.urlparse(normalize_url(domain)).hostname
        st.info("Running passive checks (non-intrusive).")

        # HTTP fetch
        target_url = normalize_url(domain)
        headers_raw = {}
        html_sample = ""
        r = safe_get(target_url)
        if r:
            headers_raw = {k: v for k,v in r.headers.items()}
            html_sample = r.text[:2000] if r.text else ""
            st.success(f"Fetched {target_url} (status {r.status_code})")
        else:
            st.error("Initial fetch failed or timed out — continuing with passive resolution.")

        # security headers
        sec_headers = {h: headers_raw.get(h, "❌ Missing") for h in SEC_HEADERS}
        sec_headers["Status Code"] = r.status_code if r else "N/A"
        sec_headers["Final URL"] = r.url if r else "N/A"

        # DNS and IPs
        dnsinfo = {}
        for rec in ["A","AAAA","MX","NS","TXT","CNAME"]:
            dnsinfo[rec] = dns_query(hostname, rec)
        ips = get_ips(hostname)
        ptrs = {ip: reverse_dns(ip) for ip in ips}

        # subdomains
        subdomains = []
        if run_subdomains:
            with st.spinner("Discovering subdomains (passive)..."):
                subdomains = discover_subdomains(hostname)

        # harvest emails
        harvest_hosts = [hostname] + (subdomains[:15] if subdomains else [])
        emails = harvest_emails(harvest_hosts)

        # WAF detection
        waf = detect_waf(headers_raw, hostname)

        # quick ports (safe)
        port_results = {}
        if run_ports and ips:
            for ip in ips[:5]:  # limit to first 5 IPs to avoid long waits
                port_results[ip] = {}
                for p in COMMON_PORTS:
                    port_results[ip][p] = check_tcp(ip,p)

        # probe APIs
        proxies_for_probes = None
        probe_headers = {"User-Agent":"SecuCheck-Probe/1.0 (+https://theclouddefender.example)"}
        api_probes = probe_apis(target_url, headers=probe_headers, proxies=None)

        # scoring basic
        cookies_flags = analyze_cookies(headers_raw.get("Set-Cookie",""))
        tls_ok = target_url.startswith("https://")
        missing = [h for h in SEC_HEADERS if "Missing" in str(sec_headers.get(h))]
        score = 100
        score -= 10 * len(missing)
        if waf == ["❌ None detected"]:
            score -= 15
        if not tls_ok:
            score -= 30
        for f in ["Secure","HttpOnly","SameSite"]:
            if cookies_flags.get(f) == "❌ Missing":
                score -= 5
        score = max(0, min(100, score))
        grade = "A" if score>90 else "B" if score>75 else "C" if score>60 else "D" if score>45 else "F"

        # show results
        st.subheader("Executive summary")
        st.write(f"Grade: **{grade}** ({score}%)")
        st.write(f"WAF/CDN detected: **{', '.join(waf)}**")
        st.write(f"Security headers missing: **{', '.join(missing) or 'None'}**")
        st.write(f"Emails found (sample): {sum(len(v) for v in emails.values())}")

        st.subheader("Details")
        with st.expander("Security headers"):
            st.json(sec_headers)
        with st.expander("DNS info (sample)"):
            st.json(dnsinfo)
        with st.expander("Resolved IPs & PTR"):
            st.json({"ips": ips, "ptrs": ptrs})
        with st.expander("Subdomains (sample)"):
            st.json(subdomains[:200])
        with st.expander("Exposed emails (sample)"):
            st.json({k:v for k,v in emails.items() if v})
        with st.expander("Quick port handshake (sample)"):
            st.json(port_results)
        with st.expander("API probes (sample)"):
            st.json(api_probes)
        with st.expander("WAF/CDN detection & tech hints"):
            st.json({"waf": waf, "html_hints": "See html sample or tech detection (not implemented here)"})

        # ---------- SIMULATION BLOCK (must have permission) ----------
        if do_simulate:
            st.warning("⚠️ Asegúrate de tener permiso del dueño del dominio para ejecutar este demo de tráfico.")
            # build proxies / worker
            proxies = None
            worker_url = None
            if use_proxy_checkbox:
                proxies = build_proxies_from_env()
                if not proxies:
                    st.error("SAFE_PROXY env var not configured. Set SAFE_PROXY if you want to use a proxy.")
            if use_worker_checkbox:
                worker_url = use_worker_url.strip() or os.environ.get("WORKER_URL")
                if not worker_url:
                    st.error("WORKER_URL not provided. Provide your worker URL or set WORKER_URL env var.")
            if (use_worker_checkbox and not worker_url) and (use_proxy_checkbox and not proxies):
                st.error("No proxy or worker set — the simulation would expose your IP. Cancel or configure a worker/proxy.")
            else:
                # minimal defaults & safety limits
                MAX_REQUESTS = min(200, int(sim_requests))
                DELAY = max(0.0, float(sim_delay))
                PATH = sim_path.strip() or "/robots.txt"
                USER_AGENT = "SecuCheck-Demo/1.0 (+https://theclouddefender.example)"

                st.info(f"Sending {MAX_REQUESTS} lightweight requests to {hostname}{PATH} (delay {DELAY}s).")
                start = time()
                stats = simulate_traffic(hostname, path=PATH, num_requests=MAX_REQUESTS, delay=DELAY,
                                         use_worker=worker_url if use_worker_checkbox else None,
                                         proxies=proxies if use_proxy_checkbox else None,
                                         user_agent=USER_AGENT)
                elapsed = time() - start
                st.success(f"Simulation completed in {elapsed:.1f}s — sent approx {MAX_REQUESTS} requests.")
                st.write(f"200 OK: {stats.get('200')}, errors: {stats.get('errors')}, other: {stats.get('other')}")
                with st.expander("Simulation details (first 30)"):
                    st.json(stats.get("details")[:30])

        st.caption("Nota: Esta herramienta realiza solo operaciones passivas y demo controlada. Para pruebas de carga o intrusivas, se requiere contrato y permiso explicito del cliente.")
