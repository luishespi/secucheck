import streamlit as st
import requests
from fpdf import FPDF, HTMLMixin

# =========================
#  Configuración inicial
# =========================
st.set_page_config(page_title="SecuCheck", page_icon="🔒")
st.title("🔒 SecuCheck — Website Security Scanner")
st.write("Audit your website security in 60 seconds. Get a grade, WAF detection, and a PDF with findings & recommendations.")

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
#  Funciones utilitarias
# =========================
def normalize_to_url(domain_or_url: str) -> str:
    dom = domain_or_url.strip()
    if not dom.startswith(("http://", "https://")):
        return f"https://{dom}"
    return dom

def safe_get(url: str):
    """Hace GET con tiempo de espera controlado."""
    return requests.get(url, timeout=12, allow_redirects=True)

# =========================
#  Módulos de análisis
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
    except Exception as e:
        out["Error"] = f"{type(e).__name__}: {e}"
        out["_raw_headers"] = {}
    return out

def detect_waf(headers_dict: dict) -> str:
    raw = " ".join([f"{k}: {v}" for k, v in headers_dict.items()]).lower()
    for waf, signs in WAF_SIGNATURES.items():
        for sig in signs:
            if sig.lower() in raw:
                return waf
    return "❌ None detected"

def simple_tls_info(url: str) -> dict:
    """Check seguro de HTTPS sin sockets crudos."""
    try:
        r = safe_get(url)
        return {
            "HTTPS used": "✅ Yes" if r.url.startswith("https://") else "❌ No",
            "Certificate": "N/A (Cloud-safe check)"
        }
    except Exception as e:
        return {"TLS Error": f"{type(e).__name__}: {e}"}

def calculate_score(headers: dict, tls_info: dict, waf_name: str):
    score = 100
    missing = [k for k in SEC_HEADERS if "Missing" in str(headers.get(k, ""))]

    score -= 10 * len(missing)
    if waf_name == "❌ None detected":
        score -= 15
    if tls_info.get("HTTPS used") == "❌ No":
        score -= 30

    score = max(0, min(100, score))
    grade = (
        "A" if score > 90 else
        "B" if score > 75 else
        "C" if score > 60 else
        "D" if score > 45 else
        "F"
    )
    return grade, score, missing

def recommendations(headers: dict, tls_info: dict, waf_name: str):
    recs = []
    if waf_name == "❌ None detected":
        recs.append("Implement a Web Application Firewall (e.g., Cloudflare WAF) to mitigate L7 threats.")
    if "Missing" in str(headers.get("Content-Security-Policy", "")):
        recs.append("Add a strong Content-Security-Policy to reduce XSS attack surface.")
    if "Missing" in str(headers.get("Strict-Transport-Security", "")):
        recs.append("Enable HSTS (Strict-Transport-Security) with preload for HTTPS enforcement.")
    if "Missing" in str(headers.get("X-Frame-Options", "")):
        recs.append("Set X-Frame-Options (DENY or SAMEORIGIN) to mitigate clickjacking.")
    if "Missing" in str(headers.get("X-Content-Type-Options", "")):
        recs.append("Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing.")
    if "Missing" in str(headers.get("Referrer-Policy", "")):
        recs.append("Set Referrer-Policy to limit referrer leakage (e.g., no-referrer-when-downgrade).")
    if tls_info.get("HTTPS used") == "❌ No":
        recs.append("Enable HTTPS with a valid TLS certificate (Let's Encrypt or provider).")
    return recs

def risk_text(grade: str) -> str:
    return (
        "🚨 High Risk: Immediate remediation recommended."
        if grade in ["D", "F"]
        else "⚠️ Medium Risk: Improvements advised."
        if grade == "C"
        else "✅ Good protection level."
    )

# =========================
#  PDF (UTF-8 seguro con fpdf2)
# =========================
class PDF(FPDF, HTMLMixin):
    def write_text(self, text):
        self.multi_cell(0, 7, text)

def generate_pdf(domain: str, headers: dict, tls: dict, waf_name: str, grade: str, score: int, missing: list, recs: list) -> str:
    pdf = PDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=16)
    pdf.cell(0, 10, "SecuCheck — Security Audit Report", ln=True, align="C")

    pdf.set_font("Helvetica", size=12)
    pdf.write_text(f"Domain: {domain}")
    pdf.write_text(f"Final URL: {headers.get('Final URL', 'N/A')}")
    pdf.ln(2)
    pdf.write_text(f"Security Grade: {grade} ({score}%)")
    pdf.write_text(f"WAF Detected: {waf_name}")
    pdf.write_text(f"Risk: {risk_text(grade)}")
    pdf.ln(5)

    pdf.write_text("HTTP Security Headers:")
    for k in SEC_HEADERS:
        pdf.write_text(f" - {k}: {headers.get(k, 'N/A')}")

    pdf.ln(2)
    pdf.write_text("TLS / HTTPS Information:")
    for k, v in tls.items():
        pdf.write_text(f" - {k}: {v}")

    if missing:
        pdf.ln(2)
        pdf.write_text("Missing headers:")
        for m in missing:
            pdf.write_text(f" - {m}")

    if recs:
        pdf.ln(3)
        pdf.write_text("Recommendations:")
        for r in recs:
            pdf.write_text(f" - {r}")

    pdf.ln(3)
    pdf.write_text("This automated report is informational and not a full penetration test.")
    fname = f"{domain.replace('https://','').replace('http://','').strip('/')}_report.pdf"
    pdf.output(fname)
    return fname

# =========================
#  Interfaz principal (UI)
# =========================
with st.form("secucheck_form", clear_on_submit=False):
    domain_input = st.text_input("Enter a domain (example.com):", value="")
    submitted = st.form_submit_button("Scan now")

if submitted:
    if not domain_input.strip():
        st.warning("Please enter a domain first.")
    else:
        url = normalize_to_url(domain_input)
        st.info("🔍 Scanning in progress...")

        headers = check_headers(url)
        tls = simple_tls_info(url)
        waf = detect_waf(headers.get("_raw_headers", {}))
        grade, score, missing = calculate_score(headers, tls, waf)
        recs = recommendations(headers, tls, waf)

        st.success("✅ Scan complete!")

        # Dashboard resumen
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Security Grade", f"{grade}", f"{score}%")
        with c2:
            st.metric("WAF", waf)
        with c3:
            st.metric("Status Code", headers.get("Status Code", "N/A"))

        st.markdown(f"**Risk:** {risk_text(grade)}")

        with st.expander("HTTP headers"):
            st.json({k: headers.get(k) for k in SEC_HEADERS})
        with st.expander("TLS / HTTPS"):
            st.json(tls)

        st.subheader("🔧 Recommendations")
        if recs:
            for r in recs:
                st.markdown(f"- {r}")
        else:
            st.markdown("- No critical gaps detected. Keep monitoring and hardening.")

        # Generar PDF
        pdf_path = generate_pdf(
            domain=domain_input,
            headers=headers,
            tls=tls,
            waf_name=waf,
            grade=grade,
            score=score,
            missing=missing,
            recs=recs
        )
        with open(pdf_path, "rb") as f:
            st.download_button(
                label="Download PDF Report",
                data=f,
                file_name=pdf_path,
                mime="application/pdf",
            )

st.caption("Powered by The Cloud Defender © 2025")
