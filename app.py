# clouddefender_modular.py
# CloudDefender – Modular Passive Exposure Scanner (Educational & Ethical)
# Author: Eton / The Cloud Defender
# NOTE: For awareness and education. Only scan domains you own or have permission to analyze.

import streamlit as st
import requests
import socket
import ssl
import json
import re
import dns.resolver
import tldextract
import whois
from bs4 import BeautifulSoup
from datetime import datetime
from time import sleep

# ===================== CONFIG =====================

st.set_page_config(page_title="CloudDefender Modular", layout="wide")
st.title("🛡️ CloudDefender – Modular Exposure Scanner (Passive & Educational)")
st.caption("Solo OSINT y reconocimiento pasivo. Úsalo para concientizar, no para atacar.")

COMMON_PORTS = [21,22,25,53,80,110,143,443,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017,5000,8081]
SEC_HEADERS = ["Strict-Transport-Security","Content-Security-Policy","X-Frame-Options","X-Content-Type-Options","Referrer-Policy"]

# ===================== HELPERS =====================

def safe_get(url, timeout=8, headers=None):
    h = {
        "User-Agent": "Mozilla/5.0 (compatible; CloudDefender/1.0)",
        "Accept": "*/*",
    }
    if headers:
        h.update(headers)
    try:
        return requests.get(url, headers=h, timeout=timeout, allow_redirects=True)
    except Exception:
        return None

def normalize_domain(d: str) -> str:
    d = d.strip()
    if not d.startswith(("http://","https://")):
        return "https://" + d
    return d

def dns_query(name, qtype):
    try:
        return [str(x) for x in dns.resolver.resolve(name, qtype)]
    except Exception:
        return []

def get_ips(domain):
    try:
        return sorted({x[4][0] for x in socket.getaddrinfo(domain, None)})
    except Exception:
        return []

def tcp_handshake(ip, port, timeout=0.5):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def cert_info(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                exp = cert.get("notAfter")
                if exp:
                    dt = datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z")
                    return {
                        "valid": True,
                        "days_left": (dt - datetime.utcnow()).days,
                        "issuer": cert.get("issuer"),
                    }
    except Exception:
        return {"valid": False}
    return {"valid": False}

def find_emails(html):
    if not html:
        return []
    rx = r"[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+"
    return sorted(set(re.findall(rx, html)))[:50]

def token_leaks(text):
    if not text:
        return []
    patterns = [
        r"sk_live_[A-Za-z0-9]{8,}",
        r"pk_live_[A-Za-z0-9]{8,}",
        r"bearer\s+[A-Za-z0-9\-\._]{10,}",
        r"api[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{10,})"
    ]
    found = []
    for p in patterns:
        found += re.findall(p, text, flags=re.IGNORECASE)
    # flatten when group returns tuples
    flat = []
    for f in found:
        if isinstance(f, tuple):
            flat.append(f[0])
        else:
            flat.append(f)
    return sorted(set(flat))[:15]

def detect_tech(html, headers):
    tech = []
    h = (html or "").lower()
    full_headers = " ".join([f"{k}:{v}" for k,v in (headers or {}).items()]).lower()
    combo = h + " " + full_headers

    if "wp-content" in combo: tech.append("WordPress")
    if "woocommerce" in combo: tech.append("WooCommerce")
    if "magento" in combo: tech.append("Magento")
    if "nginx" in combo: tech.append("Nginx")
    if "apache" in combo: tech.append("Apache")
    if "cloudflare" in combo: tech.append("Cloudflare (edge)")
    if "shopify" in combo: tech.append("Shopify")
    if "wix" in combo or "wixstatic" in combo: tech.append("Wix")
    if "react" in combo or "_next" in combo: tech.append("React / Next.js")
    return sorted(set(tech))

def estimate_traffic(domain):
    # Heurística ultra simple: no depende de servicios de pago
    # Aquí solo damos un mensaje de ejemplo, puedes cambiarlo luego.
    return {
        "rank": ">1M (no en listas públicas altas)",
        "visibility": "Low / Medium (estimado)"
    }

def get_asn_info(ip):
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if r.ok:
            j = r.json()
            return {
                "ip": ip,
                "country": j.get("country_name"),
                "org": j.get("org"),
                "asn": j.get("asn"),
            }
    except Exception:
        pass
    return {"ip": ip, "error": "lookup_failed"}

def related_domains(domain):
    base = domain.split(".")[0]
    results = []
    for tld in ["com","net","org","mx","io","co"]:
        d = f"{base}.{tld}"
        try:
            dns.resolver.resolve(d, "A")
            results.append(d)
        except Exception:
            continue
    return sorted(set(results))

def typo_domains(domain):
    base = domain.split(".")[0]
    variants = [
        base+"s",
        base[:-1],
        base+"-security",
        base.replace("o","0"),
        base+"defense"
    ]
    found=[]
    for v in variants:
        for tld in ["com","net","mx","co"]:
            d=f"{v}.{tld}"
            try:
                dns.resolver.resolve(d,"A")
                found.append(d)
            except Exception:
                continue
    return sorted(set(found))

def exposure_index(subdomains, open_ports, tech, leaks):
    score = len(subdomains)*2 + len(open_ports)*3 + len(tech)*2 + len(leaks)*5
    if score < 10:
        return "Low", score
    elif score < 25:
        return "Medium", score
    else:
        return "High", score

def crt_sh_subdomains(domain):
    out = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=6)
        if r.ok:
            data = r.json()
            for e in data:
                value = e.get("name_value","")
                for line in value.splitlines():
                    if domain in line:
                        out.add(line.strip())
    except Exception:
        pass
    return sorted(out)

# ===================== SIDEBAR (MODULE TOGGLES) =====================

st.sidebar.header("Modules")
mod_dns        = st.sidebar.checkbox("DNS & WHOIS", value=True)
mod_http       = st.sidebar.checkbox("HTTP & Security headers", value=True)
mod_tls        = st.sidebar.checkbox("TLS / Certificate", value=True)
mod_ips_ports  = st.sidebar.checkbox("IPs & Quick Port Check (safe)", value=True)
mod_subdomains = st.sidebar.checkbox("Subdomains (crt.sh passive)", value=True)
mod_tech       = st.sidebar.checkbox("Tech stack detection", value=True)
mod_emails     = st.sidebar.checkbox("Emails & token hints", value=True)
mod_asn        = st.sidebar.checkbox("ASN & GeoIP", value=True)
mod_typo       = st.sidebar.checkbox("Typo / brand variants", value=True)
mod_exposure   = st.sidebar.checkbox("Exposure score + Cloudflare recos", value=True)

st.sidebar.markdown("---")
st.sidebar.caption("ADVANCED_HOOKS: aquí puedes agregar después tus módulos de pentesting ligero SOLO para entornos controlados.")

# ===================== MAIN FORM =====================

st.markdown("---")
domain_input = st.text_input("Domain to analyze (example.com)", "")

run_btn = st.button("Run Modular Passive Scan")

if not run_btn:
    st.stop()

if not domain_input.strip():
    st.error("Por favor ingresa un dominio válido.")
    st.stop()

normalized = normalize_domain(domain_input)
hostname = tldextract.extract(normalized).registered_domain or domain_input.strip()

st.info(f"Escaneando de forma pasiva: **{hostname}** (solo OSINT / GET / DNS / TLS)")

# ===================== BASELINE HTTP REQUEST =====================

base_url = normalize_domain(hostname)
r = safe_get(base_url, timeout=10)
html = r.text if r else ""
headers = r.headers if r else {}

# ===================== MODULE EXECUTION =====================

results = {}

# --- DNS & WHOIS ---
if mod_dns:
    dns_data = {
        "A": dns_query(hostname, "A"),
        "AAAA": dns_query(hostname, "AAAA"),
        "MX": dns_query(hostname, "MX"),
        "NS": dns_query(hostname, "NS"),
        "TXT": dns_query(hostname, "TXT"),
        "CNAME": dns_query(hostname, "CNAME"),
        "SOA": dns_query(hostname, "SOA"),
    }
    try:
        who = whois.whois(hostname)
        who_data = {
            "domain": hostname,
            "created": str(who.creation_date),
            "expires": str(who.expiration_date),
            "registrar": who.registrar,
        }
    except Exception:
        who_data = {"error":"WHOIS lookup failed"}
    results["dns"] = dns_data
    results["whois"] = who_data

# --- HTTP & Security headers ---
if mod_http:
    sec_headers = {h: headers.get(h, "Missing") for h in SEC_HEADERS}
    status = r.status_code if r else "N/A"
    server = headers.get("Server","Unknown")
    results["http"] = {
        "status_code": status,
        "server": server,
        "security_headers": sec_headers,
    }

# --- TLS / Certificate ---
if mod_tls:
    cert = cert_info(hostname)
    results["tls"] = cert

# --- IPs & Ports ---
if mod_ips_ports:
    ips = get_ips(hostname)
    port_scan = []
    for ip in ips[:2]:
        for p in COMMON_PORTS:
            ok = tcp_handshake(ip, p, timeout=0.3)
            if ok:
                port_scan.append({"ip": ip, "port": p})
    results["ips"] = ips
    results["ports"] = port_scan

# --- Subdomains ---
if mod_subdomains:
    subs = crt_sh_subdomains(hostname)
    results["subdomains"] = subs

# --- Tech stack ---
if mod_tech:
    tech = detect_tech(html, headers)
    traffic = estimate_traffic(hostname)
    results["tech"] = {"stack": tech, "traffic_estimate": traffic}

# --- Emails & tokens ---
if mod_emails:
    emails = find_emails(html)
    leaks = token_leaks(html)
    results["emails"] = emails
    results["token_hints"] = leaks

# --- ASN & GeoIP ---
if mod_asn:
    ips_for_asn = results.get("ips") or get_ips(hostname)
    asn_info = [get_asn_info(ip) for ip in ips_for_asn[:5]]
    results["asn"] = asn_info

# --- Typo / brand variants ---
if mod_typo:
    typos = typo_domains(hostname)
    related = related_domains(hostname)
    results["typo"] = {
        "typo_domains_active": typos,
        "related_domains": related
    }

# --- Exposure score ---
if mod_exposure:
    subs = results.get("subdomains") or []
    ports = results.get("ports") or []
    tech = (results.get("tech") or {}).get("stack", [])
    leaks = results.get("token_hints") or []
    exposure_level, exposure_score_raw = exposure_index(subs, ports, tech, leaks)
    results["exposure"] = {
        "level": exposure_level,
        "score": exposure_score_raw
    }

# ===================== OUTPUT UI =====================

st.markdown("---")
st.header("Executive Summary")

exposure_level = results.get("exposure", {}).get("level", "N/A")
exposure_score_raw = results.get("exposure", {}).get("score", 0)
stack = (results.get("tech") or {}).get("stack", [])
traffic_est = (results.get("tech") or {}).get("traffic_estimate", {})
status = (results.get("http") or {}).get("status_code", "N/A")
server = (results.get("http") or {}).get("server", "Unknown")

st.markdown(f"- **Domain:** `{hostname}`")
st.markdown(f"- **Exposure Level:** **{exposure_level}** (score interno: {exposure_score_raw})")
st.markdown(f"- **HTTP Status:** {status}")
st.markdown(f"- **Server (header):** {server}")
st.markdown(f"- **Stack detectado:** {', '.join(stack) if stack else 'Unknown'}")
st.markdown(f"- **Tráfico estimado:** {traffic_est.get('rank','?')} — {traffic_est.get('visibility','?')}")

emails = results.get("emails") or []
token_hints = results.get("token_hints") or []
ports = results.get("ports") or []
subs = results.get("subdomains") or []

st.markdown(f"- **Emails públicos detectados (sample):** {len(emails)}")
st.markdown(f"- **Token/API key hints (frontend):** {len(token_hints)}")
st.markdown(f"- **Open ports (quick check):** {len(ports)}")
st.markdown(f"- **Subdomains (crt.sh passive):** {len(subs)}")

st.markdown("---")
st.header("Details by Module")

if mod_dns:
    with st.expander("DNS & WHOIS"):
        st.json({"dns": results.get("dns"), "whois": results.get("whois")})

if mod_http:
    with st.expander("HTTP & Security headers"):
        st.json(results.get("http"))

if mod_tls:
    with st.expander("TLS / Certificate"):
        st.json(results.get("tls"))

if mod_ips_ports:
    with st.expander("IPs & Quick Port Handshake"):
        st.json({"ips": results.get("ips"), "ports_open": results.get("ports")})

if mod_subdomains:
    with st.expander("Subdomains (crt.sh passive)"):
        st.json(results.get("subdomains"))

if mod_tech:
    with st.expander("Tech stack & Traffic estimate"):
        st.json(results.get("tech"))

if mod_emails:
    with st.expander("Emails & token hints"):
        st.json({
            "emails_public": results.get("emails"),
            "token_hints": results.get("token_hints")
        })

if mod_asn:
    with st.expander("ASN & GeoIP"):
        st.json(results.get("asn"))

if mod_typo:
    with st.expander("Typo / brand variants & related domains"):
        st.json(results.get("typo"))

if mod_exposure:
    with st.expander("Exposure Score (internal)"):
        st.json(results.get("exposure"))

# ===================== CLOUDFLARE RECOMMENDATIONS =====================

st.markdown("---")
st.header("Cloudflare-oriented Recommendations (High-level)")

recs = []

sec_headers = (results.get("http") or {}).get("security_headers", {}) if mod_http else {}
missing_headers = [h for h,v in sec_headers.items() if v == "Missing"]

if missing_headers:
    recs.append({
        "issue": f"Missing security headers: {', '.join(missing_headers)}",
        "fix": "Configurar HSTS, CSP, X-Frame-Options, X-Content-Type-Options y Referrer-Policy.",
        "cloudflare": "Usar Cloudflare Transform Rules o Workers para inyectar headers de seguridad desde el edge."
    })

if not stack or ("Cloudflare (edge)" not in stack and "WAF" not in server.lower()):
    recs.append({
        "issue": "No se detecta un WAF/CDN claro frente al sitio.",
        "fix": "Colocar la aplicación detrás de un WAF para bloqueo de ataques y caching inteligente.",
        "cloudflare": "Activar Cloudflare (Free/Pro/Enterprise) y habilitar Managed Rules + reglas personalizadas."
    })

if ports:
    recs.append({
        "issue": "Se detectan puertos expuestos accesibles desde Internet.",
        "fix": "Cerrar servicios administrativos al público y exponerlos solo vía VPN o Zero Trust.",
        "cloudflare": "Usar Cloudflare Tunnel + Access para publicar apps internas sin abrir puertos."
    })

if token_hints:
    recs.append({
        "issue": "Posibles tokens o claves visibles en frontend.",
        "fix": "Rotar claves, mover secretos a backend y revisar pipelines de CI/CD.",
        "cloudflare": "Usar Workers / Transform Rules para sanear respuestas y proteger APIs con API Shield."
    })

if subs and exposure_level in ("Medium","High"):
    recs.append({
        "issue": "Superficie digital amplia (muchos subdominios).",
        "fix": "Inventariar dominios y subdominios; aplicar controles homogéneos.",
        "cloudflare": "Centralizar DNS en Cloudflare y usar análisis de tráfico + reglas por hostname."
    })

if emails and exposure_level == "High":
    recs.append({
        "issue": "Muchos correos públicos en el sitio (phishing target).",
        "fix": "Revisar qué correos deben ser públicos y usar formularios en vez de exponerlos en texto.",
        "cloudflare": "Refuerza DMARC/DKIM/SPF y considera Email Security (según plan)."
    })

if not recs:
    st.markdown("No se detectan recomendaciones críticas inmediatas. Aun así, se pueden revisar reglas avanzadas de WAF, Bot Management y Zero Trust.")
else:
    for r in recs:
        st.markdown(f"**Issue:** {r['issue']}  \n- Fix sugerido: {r['fix']}  \n- *Cloudflare:* {r['cloudflare']}")
        st.markdown("---")

# ===================== OUTREACH TEMPLATE =====================

st.header("Plantilla de correo para CISO/CTO (resumen)")

email_template = f"""Subject: CloudDefender passive scan results for {hostname}

Hi {{Name}},

We ran a quick, non-intrusive exposure assessment of {hostname} using only public information (no exploitation, no load).

Key observations:
- Exposure level: {exposure_level} (internal score: {exposure_score_raw})
- Tech stack: {', '.join(stack) if stack else 'Unknown'}
- Public subdomains detected: {len(subs)}
- Open ports (quick handshake): {len(ports)}
- Public emails on site: {len(emails)}
- Token/API key hints in frontend: {len(token_hints)}

We use these findings as a starting point for awareness and for designing a remediation plan based on Cloudflare’s security stack (WAF, Zero Trust, Bot Management, API protection).

If you’d like, we can schedule a short session to walk you through the results and outline a remediation roadmap tailored to your environment.

Best regards,
CloudDefender Team
"""

st.code(email_template, language="text")

st.caption("⚠️ Solo para uso ético y educativo. Para pruebas activas/pentesting, se requiere autorización formal y otro tipo de herramienta/laboratorio.")
