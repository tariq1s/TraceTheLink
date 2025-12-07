# 🛡️ TraceTheLink – DFIR Analysis Suite  
Modern Digital Forensics & Incident Response tools for URL Intelligence, Redirect Forensics, and Threat Analysis.

TraceTheLink is a DFIR-grade tool designed for SOC Analysts, Threat Hunters, Incident Responders, and Malware Analysts who need to quickly understand URL redirect behavior, detect suspicious patterns, and evaluate phishing risk.

---

## 🚀 Features
### 🔗 Redirect Analyzer (Module 1 – fully implemented)
- Multi-step redirect chain extraction  
- HTTP redirect detection (301/302/307/308)  
- Meta Refresh redirect detection  
- JavaScript-based redirect detection  
- Final destination resolution  
- Redirect graph visualization (Graphviz)  
- Phishing risk scoring engine  
- Behavioral indicators  
- Clean DFIR-style UI with dark mode  

---

### ⚠️ Threat Scoring Engine (Module 2 – Coming Soon)
A more advanced threat engine is currently under development.

Planned capabilities:
- Domain reputation scoring  
- SSL certificate inspection  
- WHOIS intelligence  
- ASN & GeoIP threat risk  
- IOC correlation  
- Malicious content pattern detection  
- Full behavioral threat score (0–100)

Stay tuned for version **2.0**.

---

## 📸 Screenshots

### Homepage  
![Homepage](./screenshots/home.png)

### Redirect Analyzer  
![Redirect Analyzer](./screenshots/redirect.png)

---

## 🧰 Tech Stack
- **Python 3**
- **Streamlit** (UI framework)
- **Requests** (HTTP client)
- **BeautifulSoup4** (HTML parsing)
- **Graphviz** (Redirect visualization)
- **tldextract** (Domain parsing)

---

## 📦 Installation
```bash
git clone https://github.com/<your-username>/TraceTheLink.git
cd TraceTheLink

pip install -r requirements.txt
streamlit run app.py
