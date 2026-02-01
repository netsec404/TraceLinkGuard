# **TraceLinkGuard 🔒**

TraceLinkGuard is a FastAPI‑based security analyzer that inspects URLs and email headers for risk signals.  
It provides transparent verdicts (Allow / Medium / Block) with WHOIS details, DNS resolution, traceroute, IP geolocation, and more.

---

## 🚀 **Features**
- URL analysis with hardened risk scoring  
- WHOIS lookup (Registrar, Domain Age, Country)  
- DNS resolution + multi‑IP lookup  
- Traceroute (Windows/Linux supported)  
- IP geolocation via ipinfo.io  
- Email header analyzer (detects device/OS + SMTP Received chain)  
- Frontend UI (`web_ui.html`) with **Analyze** + **Clear** buttons  

---

## 🛠️ **Installation**

### **1. Clone the repository**
```bash
git clone https://github.com/netsec404/TraceLinkGuard.git
cd TraceLinkGuard
```

### **2. Create a virtual environment**
```bash
python -m venv venv
```

Activate it:

**Windows**
```bash
.\venv\Scripts\activate
```

**Linux / macOS**
```bash
source venv/bin/activate
```

### **3. Install dependencies**
```bash
pip install -r requirements.txt
```

---

## ▶️ **Usage**

### **Backend (FastAPI)**
Start the backend server:

```bash
uvicorn tracelinkguard:app --reload
```

This runs the API at:

```
http://127.0.0.1:8000
```

### **Frontend**
Serve the UI using Python’s built‑in server:

```bash
python -m http.server 5500
```

Open the UI in your browser:

```
http://127.0.0.1:5500/web_ui.html
```

Your UI will communicate with the backend at port **8000**.

---

## 🧪 **Testing**

### **URL Analyzer**
- **Invalid input:**  
  `abc123` → “Please enter a valid URL.”
- **Safe domain:**  
  `https://www.google.com` → “Allow: Risk = Low” + WHOIS + IP + Geo.
- **Suspicious domain:**  
  `http://suspicious-example.biz` → “Block: Risk = High” + reasons.
- **Clear button:**  
  Resets input and hides results.

### **Email Header Analyzer**
Paste raw headers or upload `.eml` to detect:
- Device/OS (Android, iPhone, Windows, macOS)  
- SMTP Received chain  

---

## 📁 **Project Structure**
```
TraceLinkGuard/
│
├── tracelinkguard.py     # FastAPI backend
├── web_ui.html           # Frontend UI
├── requirements.txt      # Python dependencies
├── README.md             # Documentation
└── .gitignore            # Git ignore rules
```