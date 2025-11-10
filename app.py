import streamlit as st
import requests, ssl, socket
from fpdf import FPDF

st.set_page_config(page_title="SecuCheck", page_icon="🔒")

st.title("🔒 SecuCheck - Website Security Scanner")
st.write("Audit your website security in 60 seconds.")

domain = st.text_input("Enter a domain (example.com):")

def check_headers(url):
    result = {}
    try:
        r = requests.get(url, timeout=10)
        headers = r.headers
        important = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]
        for h in important:
            result[h] = headers.get(h, "❌ Missing")
    except Exception as e:
        result["Error"] = str(e)
    return result

def check_tls(domain):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(5)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        return {
            "issuer": cert["issuer"],
            "valid_until": cert["notAfter"]
        }
    except Exception as e:
        return {"TLS Error": str(e)}

def generate_report(domain, headers, tls):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, f"Security Audit Report for {domain}", ln=True, align="C")
    pdf.ln(10)

    pdf.cell(200, 10, "HTTP Headers:", ln=True)
    for k, v in headers.items():
        pdf.cell(200, 8, f"{k}: {v}", ln=True)

    pdf.ln(5)
    pdf.cell(200, 10, "TLS Information:", ln=True)
    for k, v in tls.items():
        pdf.cell(200, 8, f"{k}: {v}", ln=True)

    filename = f"{domain}_report.pdf"
    pdf.output(filename)
    return filename
