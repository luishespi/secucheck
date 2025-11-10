import streamlit as st
import requests
from fpdf import FPDF

# ---- Config básica de página ----
st.set_page_config(page_title="SecuCheck", page_icon="🔒")
st.title("🔒 SecuCheck - Website Security Scanner")
st.write("Audit your website security in 60 seconds.")

# ---- Funciones de escaneo ----
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
        # Forzamos follow redirects para sitios que mueven a https o www
        r = requests.get(url, timeout=12, allow_redirects=True)
        for h in SEC_HEADERS:
            out[h] = r.headers.get(h, "❌ Missing")
        # info extra útil
        out["Status Code"] = r.status_code
        out["Final URL"] = r.url
        out["Server"] = r.headers.get("Server", "Unknown")
    except Exception as e:
        out["Error"] = f"{type(e).__name__}: {e}"
    return out

def simple_tls_info(url: str) -> dict:
    """
    Método compatible con Streamlit Cloud: NO abre sockets.
    Toma info básica del certificado si requests la expone y
    afirma si la conexión fue HTTPS.
    """
    try:
        r = requests.get(url, timeout=12, allow_redirects=True)
        tls = {
            "HTTPS used": "✅ Yes" if r.url.startswith("https://") else "❌ No",
            "Peer cert (raw)": "N/A (cloud-safe check)",
        }
        return tls
    except Exception as e:
        return {"TLS Error": f"{type(e).__name__}: {e}"}

def generate_report(domain: str, headers: dict, tls: dict) -> str:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=14)
    pdf.cell(0, 10, f"Security Audit Report for {domain}", ln=True, align="C")
    pdf.ln(5)

    pdf.set_font("Arial", size=12, style="")
    pdf.cell(0, 8, "HTTP Security Headers", ln=True)
    for k, v in headers.items():
        pdf.multi_cell(0, 7, f"{k}: {v}")

    pdf.ln(3)
    pdf.cell(0, 8, "TLS / HTTPS Information", ln=True)
    for k, v in tls.items():
        pdf.multi_cell(0, 7, f"{k}: {v}")

    fname = f"{domain}_report.pdf"
    pdf.output(fname)
    return fname

# ---- UI (aseguramos el botón con un form) ----
with st.form("secucheck_form", clear_on_submit=False):
    domain = st.text_input("Enter a domain (example.com):", value="")
    submitted = st.form_submit_button("Scan now")  # <--- AQUÍ ESTÁ EL BOTÓN

if submitted:
    if not domain.strip():
        st.warning("Please enter a domain first.")
    else:
        # Normalizamos el input a URL completa
        dom = domain.strip()
        if not dom.startswith("http://") and not dom.startswith("https://"):
            url = f"https://{dom}"
        else:
            url = dom

        st.info("🔍 Scanning in progress...")
        headers = check_headers(url)
        tls = simple_tls_info(url)
        report_path = generate_report(domain=dom, headers=headers, tls=tls)
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

# Footer
st.caption("Powered by SecuCheck © 2025")
