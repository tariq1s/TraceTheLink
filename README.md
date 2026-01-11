 TraceTheLink
Modern SOC analyst tools for URL Intelligence, Redirects, and Threat Analysis.

TraceTheLink is a tool designed for SOC Analysts, Threat Hunters, Incident Responders, and who need to quickly understand URL redirect behavior, detect suspicious patterns, and evaluate phishing risk.

---

##  Features
### 🔗 Redirect Analyzer (Module 1 – fully implemented)
- Multi-step redirect chain extraction  
- HTTP redirect detection (301/302/307/308)  
- Meta Refresh redirect detection  
- JavaScript-based redirect detection  
- Final destination resolution  
- Redirect graph visualization (Graphviz)  
- Phishing risk scoring engine  
- Behavioral indicators  
- two style UI 

---

###  Threat Scoring Engine (Module 2 – Coming Soon)
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

<img width="546" height="479" alt="4" src="https://github.com/user-attachments/assets/7aef9f67-4a57-4db4-97dc-8879a4463423" />


### Redirect Analyzer  

---<img width="514" height="716" alt="2" src="https://github.com/user-attachments/assets/2c8014c4-fee6-4c04-8042-6f4d49bdd198" />

<img width="610" height="810" alt="3" src="https://github.com/user-attachments/assets/10c1d463-9a25-4fee-a971-7c4636059802" />

##  Tech Stack
- **Python 3**
- **Streamlit** (UI framework)
- **Requests** (HTTP client)
- **BeautifulSoup4** (HTML parsing)
- **Graphviz** (Redirect visualization)
- **tldextract** (Domain parsing)

---

## Installation
```bash
git clone https://github.com/<your-username>/TraceTheLink.git
cd TraceTheLink

pip install -r requirements.txt
streamlit run app.py or python -m streamlit run app.py --server.headless true
