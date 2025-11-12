# CloudDefender - Passive Exposure Scanner (Streamlit)
# Recon pasivo y seguro para ejecutivos y CISO's. No hace ataques, ni fuzzing, ni simulaciones.
# Requiere: streamlit, requests, dnspython, beautifulsoup4, tldextract

import os, re, ssl, socket, json, urllib.parse
from datetime import datetime, timedelta
from time import sleep, time

import requests
import dns.resolver
import tldextract
import streamlit as st
from bs4 import BeautifulSoup

# ---------------- UI / Branding ----------------
st.set_page_config(page_title="CloudDefender — Passive Exposure Scanner", layout="wide")
st.title("🛡️ CloudDefender — Passive Exposure Scanner")
st.caption("Recon pasivo (DNS, WAF/CDN, headers, CORS, SPF/DMARC, subdominios, puertos, APIs, emails, hints de CVE). *Solo lectura, no intrusivo.*")

# ---------------- Constants ----------------
SEC_HEADERS = ["Strict-Transport-Security","Content-Security-Policy","X-Frame-Options","X-Content-Type-Options","Referrer-Policy"]
COMMON_PORTS = [21,22,23,25,53,80,110,135,139,143,161,443,445,465,587,993,995,1433,3306,3389,8080,8443]
CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
BUFFEROVER_URL = "https://dns.bufferover.run/dns?q=.{domain}"
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
MAILTO_REGEX = re.compile(r"mailto:([^\?\"'>]+)")
CORS_TEST_ORIGIN = "https://bad.origin.example"
TECH_HINTS = {
    "WordPress": [("meta[name='generator']", "WordPress"), ("link[href*='wp-content']", "wp")],
    "Shopify": [("script[src*='cdn.shopify.com']", "shopify")],
    "Wix": [("script[src*='wixstatic.com']", "wixstatic")],
    "Drupal": [("meta[name='generator']", "Drupal")],
    "Joomla": [("meta[name='generator']", "Joomla")],
    "Next.js": [("script[src*='_next']", "_next")],
    "React": [("div[id='root']", "react-root")],
    "Angular": [("app-root", "angular")],
}

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

TAKEOVER_CNAME_HINTS = {
    # patrón en el CNAME : proveedor
    "amazonaws.com": "AWS S3 / CloudFront",
    "cloudfront.net": "AWS CloudFront",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "azurewebsites.net": "Azure App Service",
    "storage.googleapis.com": "GCS Bucket",
    "wpengine.com": "WP Engine",
    "readthedocs.io": "ReadTheDocs",
    "zendesk.com": "Zendesk",
    "surge.sh": "Surge",
}

# ---------------- Helpers ----------------
def normalize_url(domain: str) -> str:
    d = domain.strip()
    if not d:
        return ""
    if not d.startswith(("http://", "https://")):
        return "https://" + d
    return d

def safe_get(url: str, timeout: int = 10, headers=None):
    try:
        base_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        }
        if headers:
            base_headers.update(headers)
        return requests.get(url, timeout=timeout, allow_redirects=True, headers=base_headers)
    except Exception:
        return None

def dns_query(name: str, qtype: str, lifetime: int = 6):
    try:
        return [str(r).strip() for r in dns.resolver.resolve(name, qtype, lifetime=lifetime)]
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

def cert_expiry_days(hostname: str, port: int = 443) -> dict:
    # best-effort (algunos PaaS no permiten handshake directo desde hosting)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                if not_after:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days = (exp - datetime.utcnow()).days
                    return {"valid": True, "expires_in_days": days, "issuer": str(cert.get('issuer', ''))}
    except Exception:
        pass
    return {"valid": False}

def analyze_cookies(set_cookie_header: str) -> dict:
    flags = {"Secure": "✅ Present", "HttpOnly": "✅ Present", "SameSite": "✅ Present"}
    header_lower = (set_cookie_header or "").lower()
    if "secure" not in header_lower: flags["Secure"] = "❌ Missing"
    if "httponly" not in header_lower: flags["HttpOnly"] = "❌ Missing"
    if "samesite" not in header_lower: flags["SameSite"] = "❌ Missing"
    return flags

def detect_waf(headers:dict, domain:str):
    raw = " ".join([f"{k}:{v}" for k,v in headers.items()]) if headers else ""
    raw_l = raw.lower()
    found = []
    for name, sigs in WAF_SIGNATURES.items():
        if any(sig.lower() in raw_l for sig in sigs):
            found.append(name)
    if not found:
        # CNAME hints
        cnames = dns_query(domain, "CNAME")
        for c in cnames:
            c_l = c.lower()
            if "cloudfront" in c_l: found.append("AWS CloudFront (CNAME)")
            if "cloudflare" in c_l: found.append("Cloudflare (CNAME)")
            if "akamai" in c_l: found.append("Akamai (CNAME)")
    return found if found else ["❌ None detected"]

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
                if isinstance(t, str):
                    if "," in t:
                        cand = t.split(",")[1].strip()
                        if domain in cand:
                            out.add(cand.lstrip("*."))
                    elif domain in t:
                        out.add(t.lstrip("*."))
    except Exception:
        pass
    return sorted(out)

def discover_subdomains(domain: str, limit=300):
    s = set()
    s.update(discover_crt(domain))
    s.update(discover_bufferover(domain))
    cleaned = [d.lower().strip().lstrip("*.") for d in s if domain in d]
    return sorted(set(cleaned))[:limit]

def extract_emails(html: str):
    if not html: return []
    emails = set(EMAIL_REGEX.findall(html))
    for m in MAILTO_REGEX.findall(html):
        if EMAIL_REGEX.match(m.strip()):
            emails.add(m.strip())
    try:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            if a["href"].lower().startswith("mailto:"):
                candidate = a["href"].split("mailto:")[1].split("?")[0]
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

def cors_check(url_base: str):
    try:
        r = safe_get(url_base)  # baseline
        test = safe_get(url_base, headers={"Origin": CORS_TEST_ORIGIN})
        if not test:
            return {"result": "N/A"}
        h = {k.lower(): v for k,v in test.headers.items()}
        acao = h.get("access-control-allow-origin")
        acac = h.get("access-control-allow-credentials")
        risky = False
        note = ""
        if acao == "*" and acac == "true":
            risky = True; note = "ACAO '*' con credenciales no es permitido por navegadores modernos, pero refleja mala práctica."
        if acao == CORS_TEST_ORIGIN or (acao and "*" not in acao and "http" in acao):
            # reflejar origen arbitrario es peligroso si existen endpoints que expongan datos sensibles
            risky = True; note = "ACAOrigin refleja origen arbitrario o permite origen específico externo."
        return {"allow_origin": acao, "allow_credentials": acac, "risky": risky, "note": note}
    except Exception:
        return {"result": "N/A"}

def spf_dmarc(domain: str):
    txts = dns_query(domain, "TXT")
    spf = [t for t in txts if "v=spf1" in t.lower()]
    dmarc = dns_query("_dmarc."+domain, "TXT")
    dm = "".join(dmarc) if dmarc else ""
    policy = None
    if "p=" in dm:
        try: policy = re.search(r"p=([a-zA-Z\-]+)", dm).group(1)
        except Exception: pass
    return {"spf_present": bool(spf), "spf_records": spf, "dmarc_present": bool(dmarc), "dmarc_policy": policy or "N/A"}

def tech_stack_hints(html: str):
    out = []
    try:
        soup = BeautifulSoup(html or "", "html.parser")
        for tech, rules in TECH_HINTS.items():
            for selector, marker in rules:
                try:
                    if soup.select_one(selector):
                        out.append(tech); break
                except Exception:
                    pass
        # plus raw hints
        raw = (html or "").lower()
        if "wp-content" in raw and "wordpress" not in out: out.append("WordPress")
        if "shopify" in raw and "Shopify" not in out: out.append("Shopify")
    except Exception:
        pass
    return sorted(set(out))

def cve_hint_links(techs:list):
    base = "https://nvd.nist.gov/vuln/search/results?form_type=Basic&isCpeNameSearch=false&query="
    return {t: base + urllib.parse.quote(t) for t in techs}

def public_bucket_hints(domain: str, html: str, cnames:list):
    hints = []
    raw = (html or "").lower()
    if "s3.amazonaws.com" in raw or "storage.googleapis.com" in raw:
        hints.append("HTML hints reference S3/GCS public assets — revisar políticas de acceso.")
    for c in cnames:
        cl = c.lower()
        if "amazonaws.com" in cl or "storage.googleapis.com" in cl:
            hints.append(f"CNAME apunta a {c} — verificar si el bucket/endpoint es público.")
    return sorted(set(hints))

def takeover_indicators(domain: str, cnames:list):
    suspects = []
    for c in cnames:
        cl = c.lower()
        for pat, prov in TAKEOVER_CNAME_HINTS.items():
            if pat in cl:
                suspects.append({"cname": c, "provider": prov, "advisory": "Posible subdomain takeover: verificar que el recurso exista y sea tuyo."})
                break
    return suspects

def probe_apis(base:str):
    paths = ["/api/","/api/v1/","/api/v2/","/wp-json/","/graphql","/health","/status","/.well-known/security.txt"]
    out = {}
    for p in paths:
        try:
            url = urllib.parse.urljoin(base.rstrip("/"), p.lstrip("/"))
            r = safe_get(url)
            if not r: 
                out[p] = {"status": "no_resp"}; continue
            info = {"status": r.status_code, "final_url": r.url}
            ct = r.headers.get("Content-Type","")
            if "application/json" in ct:
                try:
                    j = r.json()
                    if isinstance(j, dict):
                        info["json_keys_sample"] = list(j.keys())[:8]
                except Exception:
                    pass
            out[p] = info
        except Exception as e:
            out[p] = {"error": str(e)}
    return out

# ---------------- UI Form ----------------
with st.form("cf_form"):
    domain = st.text_input("Domain (example.com):", value="", placeholder="example.com")
    run_subdomains = st.checkbox("Descubrir subdominios (crt.sh + bufferover)", value=True)
    run_ports = st.checkbox("Comprobar puertos comunes vía handshake TCP (seguro)", value=True)
    submit = st.form_submit_button("Run CloudDefender Scan")

if not submit:
    st.stop()

if not domain.strip():
    st.error("Ingresa un dominio."); st.stop()

hostname = urllib.parse.urlparse(normalize_url(domain)).hostname
target_url = normalize_url(domain)

st.info("Ejecutando reconocimiento pasivo…")

# HTTP fetch
r = safe_get(target_url)
headers_raw = {k:v for k,v in r.headers.items()} if r else {}
html_sample = r.text[:3000] if (r and r.text) else ""

# Security headers
sec_headers = {h: headers_raw.get(h, "❌ Missing") for h in SEC_HEADERS}
sec_headers["Status Code"] = r.status_code if r else "N/A"
sec_headers["Final URL"] = r.url if r else target_url

# Cookies
cookies_flags = analyze_cookies(headers_raw.get("Set-Cookie",""))

# DNS / IPs / PTR
dnsinfo = {}
for rec in ["A","AAAA","MX","NS","TXT","CNAME","SOA"]:
    dnsinfo[rec] = dns_query(hostname, rec)
ips = get_ips(hostname)
ptrs = {ip: reverse_dns(ip) for ip in ips}

# TLS cert expiry
tls_info = cert_expiry_days(hostname)

# SPF/DMARC
email_auth = spf_dmarc(hostname)

# WAF/CDN
waf = detect_waf(headers_raw, hostname)

# Subdomains
subdomains = discover_subdomains(hostname) if run_subdomains else []

# Emails
harvest_hosts = [hostname] + (subdomains[:15] if subdomains else [])
emails = harvest_emails(harvest_hosts)

# Ports
port_results = {}
if run_ports and ips:
    for ip in ips[:5]:
        port_results[ip] = {p: check_tcp(ip,p) for p in COMMON_PORTS}

# API probes
api_probes = probe_apis(target_url)

# CORS check
cors = cors_check(target_url)

# Tech stack + CVE links
techs = tech_stack_hints(html_sample)
cves = cve_hint_links(techs)

# Public bucket hints
cname_list = dnsinfo.get("CNAME", [])
bucket_hints = public_bucket_hints(hostname, html_sample, cname_list)

# Takeover indicators
takeover = takeover_indicators(hostname, cname_list + subdomains)

# ---------- Scoring ----------
missing = [h for h in SEC_HEADERS if "Missing" in str(sec_headers.get(h))]
score = 100
score -= 8 * len(missing)
if waf == ["❌ None detected"]: score -= 12
if not email_auth["spf_present"]: score -= 8
if not email_auth["dmarc_present"]: score -= 10
if email_auth["dmarc_policy"] in ["none","N/A"]: score -= 6
if any(port_results.get(ip,{}).get(p,False) for ip in port_results for p in [22,3389,445,3306,1433]): score -= 15
if cors.get("risky"): score -= 10
if not tls_info.get("valid"): score -= 5
else:
    if tls_info.get("expires_in_days", 365) < 30: score -= 6

score = max(0, min(100, score))
grade = "A" if score>90 else "B" if score>75 else "C" if score>60 else "D" if score>45 else "F"

# ---------- Executive Summary ----------
st.subheader("Executive summary")
st.write(f"**Grade:** {grade} ({score}%)")
st.write(f"**WAF/CDN:** {', '.join(waf)}")
st.write(f"**Security headers missing:** {', '.join(missing) if missing else 'None'}")
st.write(f"**SPF/DMARC:** SPF={'✅' if email_auth['spf_present'] else '❌'}  |  DMARC={'✅' if email_auth['dmarc_present'] else '❌'} (policy: {email_auth['dmarc_policy']})")
if tls_info.get("valid"):
    st.write(f"**TLS:** certificado válido; expira en ~{tls_info['expires_in_days']} días")
else:
    st.write("**TLS:** no se pudo validar el certificado (red o PaaS bloqueó el handshake)")

# ---------- Details (expanders) ----------
st.subheader("Details")

with st.expander("Security headers"):
    st.json(sec_headers)

with st.expander("Cookies flags"):
    st.json(cookies_flags)

with st.expander("DNS records"):
    st.json(dnsinfo)

with st.expander("Resolved IPs & PTR"):
    st.json({"ips": ips, "ptrs": ptrs})

with st.expander("SPF / DMARC analysis"):
    st.json(email_auth)

with st.expander("CORS check (safe)"):
    st.json(cors)

with st.expander("WAF/CDN detection"):
    st.json({"detected": waf})

with st.expander("Subdomains (passive)"):
    st.json(subdomains[:300])

with st.expander("Exposed emails (sample)"):
    st.json({k:v for k,v in emails.items() if v})

with st.expander("Quick port handshake"):
    st.json(port_results)

with st.expander("API probes (common paths)"):
    st.json(api_probes)

with st.expander("Technology hints & CVE search links"):
    st.write("**Tech detected:**", ", ".join(techs) or "N/A")
    st.json(cves)

with st.expander("Public bucket / CDN hints"):
    st.json(bucket_hints or ["No hints found"])

with st.expander("Subdomain takeover indicators (heuristic)"):
    st.json(takeover or ["No indicators found"])

# ---------- Recommendations ----------
st.subheader("Recommendations (prioritized)")
recs = []
if missing:
    recs.append("Añadir HSTS, CSP, X-Frame-Options, X-Content-Type-Options y Referrer-Policy.")
if cors.get("risky"):
    recs.append("Restringir CORS: evita reflejar orígenes arbitrarios y no mezcles credenciales con ACAO='*'.")
if not email_auth["spf_present"]:
    recs.append("Publicar SPF (TXT v=spf1) y limitar remitentes permitidos.")
if not email_auth["dmarc_present"] or email_auth["dmarc_policy"] in ["none","N/A"]:
    recs.append("Configurar DMARC con p=quarantine o p=reject para frenar suplantación de dominio.")
if any(port_results.get(ip,{}).get(p,False) for ip in port_results for p in [22,3389,445,3306,1433]):
    recs.append("Cerrar puertos administrativos (SSH/RDP/SMB/DB) a internet o restringirlos por VPN/Zero Trust.")
if waf == ["❌ None detected"]:
    recs.append("Poner el sitio detrás de un WAF/CDN (Cloudflare Free como mínimo) y activar reglas básicas.")
if tls_info.get("valid") and tls_info.get("expires_in_days", 365) < 30:
    recs.append("Renovar certificado TLS (expira en <30 días).")
if bucket_hints:
    recs.append("Revisar permisos de buckets S3/GCS referenciados desde el sitio o CNAMEs.")
if takeover:
    recs.append("Verificar CNAMEs hacia SaaS: asegúrate de que los recursos existan (evita takeover).")
if techs:
    recs.append("Revisar CVEs relevantes para el stack detectado (ver enlaces en 'Technology hints').")

st.write("- " + "\n- ".join(recs) if recs else "✅ Sin hallazgos críticos en chequeos pasivos.")

st.caption("Solo recon pasivo. Para pruebas activas (fuzzing, carga, auth) se requiere autorización explícita.")
