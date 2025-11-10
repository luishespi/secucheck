import streamlit as st
import requests
from fpdf import FPDF, HTMLMixin

# =========================
#  Configuración inicial
# =========================
st.set_page_config(page_title="SecuCheck", page_icon="🔒")
st.title("🔒 SecuCheck — Executive Web Security Audit")
st.write("Audit public endpoints in 60 seconds. Ideal for CISO/CIO awareness reports and external exposure assessments.")

# =========================
#  Constantes y firmas
# =========================
SEC_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare", "cf-"],
    "Akamai": ["akamai", "ghost", "akamai-"],
    "Imperva": ["incapsula", "x-iinfo"],
    "AWS (ALB/ELB/WAF)": ["awsalb", "awselb"],
    "Fastly": ["fastly"],
    "Sucuri": ["x-sucuri-id", "sucuri"],
    "F5": ["bigip", "x-waf-event"]
}

# =========================
#  Funciones base
# =========================
def normalize_to_url(domain_or_url: str) -> str:
    dom = domain_or_url.strip()
    if not dom.startswith(("http://", "https://")):
        return f"https://{dom}"
    return dom

def safe_get(url: str):
    return requests.get(url, timeout=10, allow_redirects=True)

# =========================
#  Escaneos
# =========================
def check_headers(url: str) -> dict:
    out = {}
    try:
        r = safe_get(url)
        for h in SEC_HEADERS:
            out[h] = r.headers.get(h, "❌ Missing")
        out["Status Code"] = r.status_code
        out["Final URL"] = r.url
        out["Server"] = r.headers.get("Server", "Unknown")
        out["_raw_headers"] = {k.lower(): v for k, v in r.headers.items()}
        out["_cookies"] = r.headers.get("Set-Cookie", "")
    except Exception as e:
        out["Error"] = str(e)
        out["_raw_headers"] = {}
    return out

def detect_waf(headers_dict: dict) -> str:
    raw = " ".join([f"{k}: {v}" for k, v in headers_dict.items()]).lower()
    for waf, signs in WAF_SIGNATURES.items():
        if any(sig.lower() in raw for sig in signs):
            return waf
    return "❌ None detected"

def simple_tls_info(url: str) -> dict:
    try:
        r = safe_get(url)
        return {"HTTPS used": "✅ Yes" if r.url.startswith("https://") else "❌ No"}
    except Exception as e:
        return {"TLS Error": str(e)}

def analyze_cookies(cookie_str: str) -> dict:
    if not cookie_str:
        return {"Cookies found": "❌ None"}
    flags = {"Secure": "❌ Missing", "HttpOnly": "❌ Missing", "SameSite": "❌ Missing"}
    if "secure" in cookie_str.lower():
        flags["Secure"] = "✅ Present"
    if "httponly" in cookie_str.lower():
        flags["HttpOnly"] = "✅ Present"
    if "samesite" in cookie_str.lower():
        flags["SameSite"] = "✅ Present"
    return flags

def detect_tech_exposure(headers: dict) -> list:
    exposure = []
    if headers.get("Server") and headers["Server"] not in ["Unknown", ""]:
        exposure.append(f"Server header reveals: {headers['Server']}")
    raw = " ".join(headers.get("_raw_headers", {}).keys())
    if "x-powered-by" in raw:
        exposure.append("X-Powered-By header exposes backend technology.")
    return exposure

def risk_text(grade: str):
    return "🚨 High Risk" if grade in ["D", "F"] else "⚠️ Medium Risk" if grade == "C" else "✅ Good"

# =========================
#  PDF (fpdf2)
# =========================
class PDF(FPDF, HTMLMixin):
    pass

def generate_pdf(domain, headers, tls, waf, grade, score, cookies, exposure, recs):
    pdf = PDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=16)
    pdf.cell(0, 10, "SecuCheck — Executive Security Report", ln=True, align="C")

    pdf.set_font("Helvetica", size=12)
    pdf.multi_cell(0, 8, f"Domain: {domain}")
    pdf.multi_cell(0, 8, f"Final URL: {headers.get('Final URL','N/A')}")
    pdf.multi_cell(0, 8, f"Grade: {grade} ({score}%) — {risk_text(grade)}")
    pdf.multi_cell(0, 8, f"WAF Detected: {waf}")
    pdf.ln(5)

    pdf.multi_cell(0, 8, "HTTP Security Headers:")
    for k in SEC_HEADERS:
        pdf.multi_cell(0, 8, f" - {k}: {headers.get(k, 'N/A')}")

    pdf.ln(4)
    pdf.multi_cell(0, 8, "Cookie Security Flags:")
    for k, v in cookies.items():
        pdf.multi_cell(0, 8, f" - {k}: {v}")

    if exposure:
        pdf.ln(4)
        pdf.multi_cell(0, 8, "Technology Exposure:")
        for e in exposure:
            pdf.multi_cell(0, 8, f" - {e}")

    pdf.ln(5)
    pdf.multi_cell(0, 8, "Recommendations:")
    for r in recs:
        pdf.multi_cell(0, 8, f" - {r}")

    pdf.ln(6)
    pdf.multi_cell(0, 8, "Executive Summary:")
    pdf.multi_cell(0, 8,
        "This external review identifies missing application security headers, "
        "unsecured cookies, and exposed technologies that may increase your attack surface. "
        "Mitigation through WAF, strict HTTPS enforcement, and security headers is recommended."
    )

    fname = f"{domain.replace('https://','').replace('http://','').strip('/')}_report.pdf"
    pdf.output(fname)
    return fname

# =========================
#  Interfaz
# =========================
with st.form("scan"):
    dom = st.text_input("Enter a domain:", value="")
    submit = st.form_submit_button("Run Executive Audit")

if submit:
    if not dom:
        st.warning("Enter a valid domain.")
    else:
        url = normalize_to_url(dom)
        st.info("🔍 Scanning in progress...")

        headers = check_headers(url)
        waf = detect_waf(headers.get("_raw_headers", {}))
        tls = simple_tls_info(url)
        cookies = analyze_cookies(headers.get("_cookies", ""))
        exposure = detect_tech_exposure(headers)

        missing = [h for h in SEC_HEADERS if "Missing" in str(headers.get(h,""))]
        score = 100 - (len(missing)*10)
        if waf == "❌ None detected":
            score -= 10
        if cookies.get("Secure") == "❌ Missing":
            score -= 10
        grade = "A" if score>90 else "B" if score>75 else "C" if score>60 else "D" if score>45 else "F"

        recs = []
        if missing: recs.append("Implement missing security headers.")
        if waf == "❌ None detected": recs.append("Deploy a WAF or application firewall.")
        if "❌ Missing" in cookies.values(): recs.append("Harden cookies with Secure, HttpOnly, SameSite flags.")
        if exposure: recs.append("Remove Server/X-Powered-By headers to reduce fingerprinting.")
        if tls.get("HTTPS used") == "❌ No": recs.append("Enable HTTPS with HSTS enforcement.")

        st.success("✅ Audit complete.")
        st.metric("Security Grade", f"{grade}", f"{score}%")
        st.metric("WAF", waf)
        st.metric("Cookies", cookies.get("Secure","N/A"))

        with st.expander("HTTP Headers"):
            st.json(headers)
        with st.expander("Cookies"):
            st.json(cookies)
        with st.expander("Technology Exposure"):
            st.json(exposure)

        pdf_path = generate_pdf(dom, headers, tls, waf, grade, score, cookies, exposure, recs)
        with open(pdf_path, "rb") as f:
            st.download_button("📄 Download Executive PDF", f, file_name=pdf_path)

st.caption("The Cloud Defender — External Exposure Awareness Tool © 2025")
