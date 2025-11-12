# clouddefender_app.py
"""
CloudDefender — Passive + Ethical-Aggressive Exposure Scanner (Streamlit)
Safe: solo GET/HEAD/TCP handshakes ligeros. No fuzzing, no brute force, no DDoS.
Propósito: generar evidencia convincente para CISO/CFO y recomendaciones (incluye propuestas Cloudflare).
"""

import re, socket, ssl, urllib.parse, json, time
from datetime import datetime
from time import sleep

import requests
import dns.resolver
import tldextract
import whois
from bs4 import BeautifulSoup
import streamlit as st

# ---------------- UI / Config ----------------
st.set_page_config(page_title="CloudDefender", layout="wide")
st.title("🛡️ CloudDefender — Passive + Ethical-Aggressive Scanner")
st.markdown("Recon pasivo y pruebas seguras (lectura). **No** realiza ataques. Para pruebas activas se pide autorización por escrito.")

# ---------------- Constants ----------------
COMMON_PORTS = [
    # Web & proxies
    80,443,8080,8443,8888,
    # Admin
    22,3389,5900,5985,5986,
    # Databases
    3306,5432,1433,1521,27017,6379,9200,
    # Mail / LDAP
    25,110,143,465,587,993,995,389,636,
    # Files / SMB
    21,23,139,445,2049,111,873,
    # Monitoring / Dev
    161,5601,15672,9092,9090,2181,3000,8081,5000,2375,4243
]

SEC_HEADERS = ["Strict-Transport-Security","Content-Security-Policy","X-Frame-Options","X-Content-Type-Options","Referrer-Policy"]
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray","cf-cache-status","server: cloudflare","cf-"],
    "Akamai": ["akamai","akamaiedge"],
    "Imperva": ["incapsula","x-iinfo"],
    "AWS CloudFront": ["cloudfront","x-amz-cf-id"],
    "Fastly": ["fastly"],
    "Sucuri": ["x-sucuri-id","sucuri"],
    "Azure Frontdoor": ["azurefd","x-azure-ref"],
}

TAKEOVER_CNAME_HINTS = {
    "github.io":"GitHub Pages",
    "herokuapp.com":"Heroku",
    "azurewebsites.net":"Azure App Service",
    "s3.amazonaws.com":"AWS S3",
    "storage.googleapis.com":"GCS",
    "wpengine.com":"WP Engine",
}

CORS_TEST_ORIGIN = "https://bad.origin.example"
EMAIL_RX = re.compile(r"[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+")

# ---------------- Helpers ----------------
def normalize(domain: str) -> str:
    d = domain.strip()
    if not d.startswith(("http://","https://")):
        return "https://" + d
    return d

def safe_get(url, timeout=8, headers=None):
    hdr = {"User-Agent": "Mozilla/5.0 (compatible; CloudDefender/1.0)", "Accept": "*/*"}
    if headers:
        hdr.update(headers)
    try:
        r = requests.get(url, timeout=timeout, headers=hdr, allow_redirects=True)
        return r
    except Exception:
        return None

def dns_query(name, qtype, lifetime=5):
    try:
        return [str(x).strip() for x in dns.resolver.resolve(name, qtype, lifetime=lifetime)]
    except Exception:
        return []

def get_ips(hostname):
    try:
        ai = socket.getaddrinfo(hostname, None)
        return sorted({x[4][0] for x in ai})
    except Exception:
        return []

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def tcp_handshake(ip, port, timeout=0.6):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def cert_info(hostname, port=443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                notafter = cert.get("notAfter")
                if notafter:
                    exp = datetime.strptime(notafter, "%b %d %H:%M:%S %Y %Z")
                    return {"valid": True, "expires_days": (exp - datetime.utcnow()).days, "issuer": cert.get("issuer")}
    except Exception:
        pass
    return {"valid": False}

def analyze_cookies(set_cookie):
    s = (set_cookie or "").lower()
    return {
        "Secure": "✅" if "secure" in s else "❌",
        "HttpOnly": "✅" if "httponly" in s else "❌",
        "SameSite": "✅" if "samesite" in s else "❌"
    }

def detect_waf(headers, domain):
    raw = " ".join([f"{k}:{v}" for k,v in (headers or {}).items()]).lower()
    found=[]
    for k, sigs in WAF_SIGNATURES.items():
        if any(sig in raw for sig in sigs):
            found.append(k)
    # CNAME hint
    cn = dns_query(domain,"CNAME")
    for c in cn:
        cl = c.lower()
        if "cloudfront" in cl and "AWS CloudFront" not in found: found.append("AWS CloudFront (CNAME)")
        if "cloudflare" in cl and "Cloudflare (CNAME)" not in found: found.append("Cloudflare (CNAME)")
    return found or ["❌ None detected"]

# ---------- Ethical-Aggressive detectors (safe reads) ----------

def token_leak_detector(text):
    if not text: return []
    patterns = [
        r"api[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{8,})['\"]?",
        r"sk_live_[A-Za-z0-9]{8,}",
        r"pk_live_[A-Za-z0-9]{8,}",
        r"pk_test_[A-Za-z0-9]{8,}",
        r"bearer\s+([A-Za-z0-9\-\._]{8,})",
        r"paypal[_\-]?client[_\-]?id",
        r"stripe[_\-]?(key|client|pk|sk)"
    ]
    leaks=set()
    for p in patterns:
        for m in re.findall(p, text, flags=re.IGNORECASE):
            leaks.add((p, m if isinstance(m,str) else (m[0] if isinstance(m,tuple) else str(m))))
    return list(leaks)

def js_source_audit(html, base):
    scripts = []
    try:
        soup = BeautifulSoup(html or "", "html.parser")
        for s in soup.find_all("script", src=True):
            src = s.get("src")
            if not src: continue
            full = urllib.parse.urljoin(base, src)
            scripts.append(full)
    except Exception:
        pass
    report={}
    for s in scripts[:5]:
        r = safe_get(s, timeout=6)
        if not r: continue
        sample = r.text[:4000]
        tokens = token_leak_detector(sample)
        report[s] = {"status": r.status_code, "size_kb": len(r.text)//1024, "token_hints": tokens[:5]}
        time.sleep(0.25)
    return report

def ecommerce_endpoints_check(base):
    targets = [
        "/cart","/checkout","/order","/orders","/api/checkout","/api/cart",
        "/payment","/api/payment","/billing","/api/billing","/payment_intents",
        "/graphql","/api/v1/checkout","/api/v1/orders","/wp-json/wc/v3/orders"
    ]
    findings={}
    for p in targets:
        url = urllib.parse.urljoin(base, p.lstrip("/"))
        r = safe_get(url, timeout=6)
        if not r: continue
        ct = r.headers.get("Content-Type","")
        info={"status": r.status_code, "content_type": ct}
        if "application/json" in ct:
            try:
                j = r.json()
                if isinstance(j, dict):
                    info["json_keys_sample"] = list(j.keys())[:8]
            except Exception:
                pass
        findings[url]=info
        sleep(0.2)
    return findings

def error_leakage_detector(base, html):
    # look in main page + common debug paths for strings indicating stacktraces or DB errors
    indicators=["traceback","exception","sql syntax","fatal error","stacktrace","java.lang","php error","uncaught exception","at com."]
    leaks={}
    urls=[base, urllib.parse.urljoin(base,"/debug"), urllib.parse.urljoin(base,"/status"), urllib.parse.urljoin(base,"/api/health")]
    for u in urls:
        r = safe_get(u, timeout=5)
        if not r: continue
        text = (r.text or "").lower()[:6000]
        matches=[i for i in indicators if i in text]
        if matches:
            leaks[u] = {"status": r.status_code, "matches": sorted(matches)}
        sleep(0.2)
    return leaks

def graphql_introspection_probe(base):
    # very light: send a POST with a small introspection query (safe, read-only)
    url = urllib.parse.urljoin(base, "/graphql")
    payload = {"query":"{ __schema { queryType { name } } }"}
    try:
        r = requests.post(url, json=payload, timeout=5, headers={"User-Agent":"CloudDefender/1.0"})
        if r and r.status_code==200:
            j = None
            try: j = r.json()
            except Exception: pass
            return {"status": r.status_code, "json_sample_keys": list(j.keys())[:6] if isinstance(j,dict) else None}
    except Exception:
        pass
    return {}

def public_bucket_hint_detector(html, cnames):
    hints=[]
    raw=(html or "").lower()
    if "s3.amazonaws.com" in raw or ".s3.amazonaws.com" in raw:
        hints.append("References to s3.amazonaws.com found in HTML — revisar permisos del bucket.")
    if "storage.googleapis.com" in raw:
        hints.append("References to storage.googleapis.com found — revisar permisos GCS.")
    for c in cnames:
        cl=c.lower()
        if "amazonaws.com" in cl:
            hints.append(f"CNAME {c} apunta a AWS — verificar si es bucket público.")
        if "storage.googleapis.com" in cl:
            hints.append(f"CNAME {c} apunta a GCS — verificar si es bucket público.")
    return hints

def takeover_heuristic(domain, cnames, subdomains):
    suspects=[]
    for c in cnames + subdomains:
        cl=c.lower()
        for pat, prov in TAKEOVER_CNAME_HINTS.items():
            if pat in cl:
                suspects.append({"target":c,"provider":prov,"advisory":"Possible take-over vector — verify resource ownership"})
    return suspects

def spf_dmarc(domain):
    txts = dns_query(domain, "TXT")
    spf = [t for t in txts if "v=spf1" in t.lower()]
    dmarc = dns_query("_dmarc."+domain, "TXT")
    policy = None
    if dmarc:
        m = re.search(r"p=([a-zA-Z\-]+)", " ".join(dmarc))
        if m: policy = m.group(1)
    return {"spf": bool(spf), "dmarc": bool(dmarc), "dmarc_policy": policy or "N/A", "spf_records": spf}

def cve_hint_links(techs):
    base = "https://nvd.nist.gov/vuln/search/results?query="
    return {t: base + urllib.parse.quote(t) for t in techs}

def tech_hint_detector(html):
    hints=[]
    raw=(html or "").lower()
    if "wp-content" in raw: hints.append("WordPress")
    if "woocommerce" in raw: hints.append("WooCommerce")
    if "shopify" in raw: hints.append("Shopify")
    if "wixstatic" in raw: hints.append("Wix")
    if "_next" in raw: hints.append("Next.js/React")
    if "magento" in raw: hints.append("Magento")
    return sorted(set(hints))

def whois_info(domain):
    try:
        d = whois.whois(domain)
        return {"domain": domain, "created": str(d.creation_date), "expires": str(d.expiration_date), "registrar": d.registrar}
    except Exception:
        return {}

# ---------- Main UI form ----------
with st.form("scan"):
    col1, col2 = st.columns([3,1])
    with col1:
        domain_input = st.text_input("Domain (example.com)", value="", placeholder="example.com")
    with col2:
        scan_sub = st.form_submit_button("Run Deep Passive Scan (safe)")
st.markdown("---")
if not scan_sub:
    st.info("Ingresa un dominio y presiona 'Run Deep Passive Scan (safe)'")
    st.stop()

if not domain_input.strip():
    st.error("Ingresa un dominio válido."); st.stop()

target = domain_input.strip()
base_url = normalize(target)
hostname = urllib.parse.urlparse(base_url).hostname

st.success(f"Starting CloudDefender scan for {hostname} — safe passive checks only. Please allow ~20s.")

# ---------- baseline fetch ----------
r = safe_get(base_url)
headers = r.headers if r else {}
html = r.text if r and r.text else ""

# ---------- Basic findings ----------
sec = {h: headers.get(h, "❌ Missing") for h in SEC_HEADERS}
sec["Status"] = r.status_code if r else "N/A"
cookies_flags = analyze_cookies(headers.get("Set-Cookie",""))
ips = get_ips(hostname)
ptrs = {ip: reverse_dns(ip) for ip in ips}
dns_all = {t: dns_query(hostname, t) for t in ["A","AAAA","MX","NS","TXT","CNAME","SOA"]}

tls = cert_info(hostname)
waf = detect_waf(headers, hostname)
spf = spf_dmarc(hostname)
who = whois_info(hostname)
techs = tech_hint_detector(html)
cve_links = cve_hint_links(techs)

# ---------- Ethical-aggressive modules ----------
# 1 Token leaks
token_leaks = token_leak_detector(html)

# 2 JS audit
js_audit = js_source_audit(html, base_url)

# 3 Ecommerce endpoints
ecom = ecommerce_endpoints_check(base_url)

# 4 Error leakage
err_leaks = error_leakage_detector(base_url, html)

# 5 GraphQL light probe
graphql = graphql_introspection_probe(base_url)

# 6 Public bucket hints
cname_list = dns_all.get("CNAME",[])
bucket_hints = public_bucket_hint_detector(html, cname_list)

# 7 Subdomain takeovers heuristic
# passive subdomain discovery (crt.sh)
def crt_sh_subs(domain):
    out=set()
    try:
        url=f"https://crt.sh/?q=%25.{domain}&output=json"
        r=requests.get(url, timeout=6)
        if r.status_code==200:
            data=r.json()
            for e in data:
                nv=e.get("name_value","")
                for line in nv.splitlines():
                    if domain in line:
                        out.add(line.strip().lstrip("*."))
    except Exception:
        pass
    return sorted(out)

subdomains = crt_sh_subs(hostname)[:300]
takeover = takeover_heuristic(hostname, cname_list, subdomains)

# 8 TLS/SSL analyzer (basic)
ssl_issues = []
if tls.get("valid"):
    if tls.get("expires_days",999) < 30:
        ssl_issues.append("Certificate expiring in <30 days")
else:
    ssl_issues.append("Could not validate certificate (handshake failed)")

# 9 Port quick handshake (safe): only test first 3 IPs and only short timeout
port_results={}
for ip in ips[:3]:
    port_results[ip] = {}
    for p in COMMON_PORTS:
        # skip too noisy ports for public demo? we'll keep it short timeout
        try:
            ok = tcp_handshake(ip,p, timeout=0.5)
            port_results[ip][p] = ok
        except Exception:
            port_results[ip][p] = False

# 10 HIBP (optional): check if any harvested emails appear in breaches (requires API key)
# We'll only detect emails from public pages and offer guidance — not auto-query HIBP unless env var provided
harvested_emails = []
# harvest from homepage and common pages
def find_emails_in_html(text):
    return list(set(EMAIL_RX.findall(text or "")))
harvested_emails += find_emails_in_html(html)
for p in ["/contact","/about","/security.txt","/robots.txt"]:
    try:
        rr = safe_get(urllib.parse.urljoin(base_url,p))
        if rr and rr.status_code==200:
            harvested_emails += find_emails_in_html(rr.text)
    except Exception:
        pass
harvested_emails = sorted(set(harvested_emails))[:50]

# ---------- Scoring ----------
score = 100
missing_headers = [h for h in SEC_HEADERS if "Missing" in str(sec.get(h))]
score -= 6 * len(missing_headers)
if waf == ["❌ None detected"]: score -= 12
if not spf.get("spf"): score -= 8
if not spf.get("dmarc"): score -= 10
if token_leaks: score -= 20
if any(any(port_results[ip].get(p) for p in [22,3389,445,3306,1433]) for ip in port_results): score -= 15
if err_leaks: score -= 10
if ssl_issues: score -= 6
if bucket_hints: score -= 8
if takeover: score -= 12
score = max(0,min(100,score))
grade = "A" if score>90 else "B" if score>75 else "C" if score>60 else "D" if score>45 else "F"

# ---------- Executive summary ----------
st.header("Executive summary")
st.markdown(f"**Grade:** {grade} ({score}%)")
st.markdown(f"**WAF/CDN:** {', '.join(waf)}")
st.markdown(f"**Missing security headers:** {', '.join(missing_headers) if missing_headers else 'None'}")
st.markdown(f"**SPF/DMARC:** SPF={'✅' if spf['spf'] else '❌'} | DMARC={'✅' if spf['dmarc'] else '❌'} (policy: {spf['dmarc_policy']})")
if tls.get("valid"):
    st.markdown(f"**TLS:** certificado válido — expira en ~{tls.get('expires_days')} días")
else:
    st.markdown("**TLS:** handshake no validado (PaaS o bloqueo).")

# financial estimator tiny (example)
monthly_revenue = st.number_input("Optional: Monthly revenue (USD) to estimate impact", value=0.0, step=100.0)
if monthly_revenue and score < 70:
    # naive estimator:
    breach_prob = (100 - score)/100.0 * 0.2   # example
    avg_breach_cost = max(100000, monthly_revenue*2) 
    expected_annual_loss = breach_prob * avg_breach_cost
    st.markdown(f"**Estimated annual loss (very rough):** ${expected_annual_loss:,.0f} (based on score & revenue)")

st.markdown("---")

# ---------- Details expanders ----------
with st.expander("Security headers"):
    st.json(sec)

with st.expander("Cookies flags"):
    st.json(cookies_flags)

with st.expander("DNS & WHOIS"):
    st.json({"dns": dns_all, "whois": who})

with st.expander("Resolved IPs & PTR"):
    st.json({"ips": ips, "ptrs": ptrs})

with st.expander("WAF / CDN detection"):
    st.json(waf)

with st.expander("TLS info & issues"):
    st.json({"tls": tls, "issues": ssl_issues})

with st.expander("SPF / DMARC analysis"):
    st.json(spf)

with st.expander("Harvested emails (sample)"):
    st.json(harvested_emails or ["No public emails found"])

with st.expander("Token leaks found in HTML"):
    st.json(token_leaks or ["No token patterns found in main HTML"])

with st.expander("JS source audit (top scripts)"):
    st.json(js_audit or {"info":"No public scripts or nothing suspicious"})

with st.expander("Ecommerce & payment endpoints (safe probes)"):
    st.json(ecom or {"info":"No common endpoints detected"})

with st.expander("GraphQL introspection (light probe)"):
    st.json(graphql or {"info":"No accessible GraphQL or no introspection data returned"})

with st.expander("Error leakage (stacktraces / DB errors)"):
    st.json(err_leaks or {"info":"No obvious error leakage detected"})

with st.expander("Public bucket / CDN hints"):
    st.json(bucket_hints or ["No public bucket hints in HTML/CNAMEs"])

with st.expander("Subdomains (crt.sh passive)"):
    st.json(subdomains[:200] or ["No passive subdomains found"])

with st.expander("Subdomain takeover heuristic"):
    st.json(takeover or ["No takeover indicators"])

with st.expander("Quick port handshake (safe)"):
    st.json(port_results)

with st.expander("Technology hints & CVE search links"):
    st.json({"techs": techs, "cve_links": cve_links})

# ---------- Recommendations mapped to Cloudflare services ----------
st.header("Recommendations & How Cloudflare helps (examples)")
reco = []
if missing_headers:
    reco.append({
        "issue":"Security headers missing",
        "fix":"Configure HSTS, Content-Security-Policy, X-Frame-Options and X-Content-Type-Options on origin or via Cloudflare Transform Rules / Page Rules.",
        "cloudflare":"Use Cloudflare Rules to add security headers at the edge (Workers or Transform Rules)."
    })
if waf == ["❌ None detected"]:
    reco.append({
        "issue":"No WAF / CDN detected",
        "fix":"Place site behind a WAF / CDN — block known bad bots, enable OWASP rules.",
        "cloudflare":"Cloudflare Free includes basic WAF protections, enable Managed Rules + custom WAF rules for checkout endpoints."
    })
if token_leaks:
    reco.append({
        "issue":"Exposed tokens/keys in frontend",
        "fix":"Rotate exposed keys immediately. Move secrets to server-side. Review CI/CD pipelines.",
        "cloudflare":"Use Cloudflare Access / Zero Trust for backend APIs, and set up API Tokens and RBAC for internal services."
    })
if any(p for ip in port_results for p in port_results[ip] if port_results[ip][p] and p in [22,3389,3306,1433,445]):
    reco.append({
        "issue":"Administrative ports reachable from Internet",
        "fix":"Close administrative ports at firewall; expose only via VPN or Zero Trust Access.",
        "cloudflare":"Cloudflare Access + Cloudflare Tunnel (warp/Argo Tunnel) to expose apps without opening public ports."
    })
if bucket_hints:
    reco.append({
        "issue":"Public buckets referenced",
        "fix":"Ensure S3/GCS buckets are private; use signed URLs for assets.",
        "cloudflare":"Use Cloudflare R2 + signed URLs or restrict origin to Cloudflare only and use Origin Access."
    })
if takeover:
    reco.append({
        "issue":"Possible subdomain takeover",
        "fix":"Verify and claim dangling CNAME targets or remove CNAMEs.",
        "cloudflare":"Use DNS monitoring and alerting; fix/remove dangling CNAMEs and add monitoring to CloudDefender."
    })

for r in reco:
    st.markdown(f"**{r['issue']}** — {r['fix']}  \n*Cloudflare suggestion:* {r['cloudflare']}")

if not reco:
    st.markdown("No prioritized Cloudflare recommendations — run advanced checks or autorize deeper scan.")

st.markdown("---")

# ---------- Sales / outreach template ----------
st.header("Suggested outreach email to CISO (short)")
st.code(f"""Subject: CloudDefender quick scan results for {hostname}

Hi {{Name}},

I ran a quick, non-intrusive scan of {hostname} (public surface). Key highlights:
- Grade: {grade} ({score}%)
- Missing security headers: {', '.join(missing_headers) if missing_headers else 'None'}
- WAF/CDN: {', '.join(waf)}
- Token leaks: {len(token_leaks)}
- Public emails found: {len(harvested_emails)}

We can run an authorized deep assessment (includes safe API checks, token audits, and remediation plan). We also offer Cloudflare-based mitigations (WAF, Access, Tunnel, R2) and a 30-day remediation playbook.

If you want, I can schedule a 30-min walkthrough and share a tailored remediation estimate.

Regards,
Your Team - CloudDefender
""")

st.caption("⚠️ Legal reminder: this tool runs **safe** public checks. For active testing (auth tests, fuzzing, load tests) get written authorization.")

# End
