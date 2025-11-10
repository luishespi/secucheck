import streamlit as st
import requests
from fpdf import FPDF

# ---- Configuración de página ----
st.set_page_config(page_title="SecuCheck", page_icon="🔒")
st.title("🔒 SecuCheck - Website Security Scanner")
st.write("Audit your website security in 60 seconds.")

# ---- Funciones ----
SEC_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]

def check_headers(url: str) -> dict:
    out = {}
    try:
        r = requests.get(url, timeout=12, allow_redirects=True)
        for h in SEC_HEADERS:
            out[h] = r.headers.get(h, "❌ Missing")
        out["Status Code"] = r.status_code
        out["Final URL"] = r.url
        out["Server"] = r.headers.get("Server", "Unknown")
    except Exception as e:
        out["Error"] = f"{type(e).__name__}: {e}"
    return out

def simple_tls_info(url: str) -> dict:
    try:
        r = requests.get(url, timeout=12, allow_redirects=True)
        return {
            "HTTPS used": "✅ Yes" if r.url.startswith("https://") else "❌ No",
            "Certificate": "N/A (Cloud-safe check)",
        }
    except Exception as e:
        return {"TLS Error": f"{type(e).__name__}: {e}"}

class PDF(FPDF):
    def write_text(self, text):
        # Evita errores de codificación reemplazando caracteres fuera de latin-1
        safe_text = text.encode("latin-1", "replace").decode("latin-1")
        self.multi_cell(0, 7, safe_text)

def generate_report(domain: str, headers: dict, tls: dict) -> str:
    pdf = PDF()
    pdf.add_page()
    pdf.set_font("Arial", size=14)
    pdf.cell(0, 10, f"Security Audit Report for {domain}", ln=True, align="C")
    pdf.ln(8)

    pdf.set_font("Arial", size=12)
    pdf.write_text("HTTP Security Headers:")
    pdf.ln(5)
    for k, v in headers.items():
        pdf.write_text(f"{k}: {v}")
    pdf.ln(5)
    pdf.write_text("TLS / HTTPS Information:")
    for k, v in tls.items():
        pdf.write_text(f"{k}: {v}")

    filename = f"{domain}_report.pdf"
    pdf.output(filename)
    return filename

# ---- Interfaz ----
with st.form("secucheck_form", clear_on_submit=False):
    domain = st.text_input("Enter a domain (example.com):", value="")
    submitted = st.form_submit_button("Scan now")

if submitted:
    if not domain.strip():
        st.warning("Please enter a domain first.")
    else:
        if not domain.startswith("http://") and not domain.startswith("https://"):
            url = f"https://{domain.strip()}"
        else:
            url = domain.strip()

        st.info("🔍 Scanning in progress...")
        headers = check_headers(url)
        tls = simple_tls_info(url)
        report_path = generate_report(domain, headers, tls)
        st.success("✅ Scan complete!")

        st.subheader("Results (preview)")
        st.json({"headers": headers, "tls": tls})

        with open(report_path, "rb") as f:
            st.download_button(
                label="Download PDF Report",
                data=f,
                file_name=report_path,
                mime="application/pdf",
            )

st.caption("Powered by SecuCheck © 2025")
