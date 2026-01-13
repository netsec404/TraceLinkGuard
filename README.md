# Link Guard — Professional tracelinkguard

Trace Link Guard is a FastAPI-based security tracelinkguard that analyzes URLs and email headers for risk signals.  
It provides verdicts (Allow / Warn / Block) with transparent reasons, WHOIS details, DNS resolution, traceroute, and IP geolocation.

---

## 🚀 Features
- URL analysis with risk scoring
- WHOIS lookup (Registrar, Domain Age)
- DNS resolution and traceroute
- IP geolocation via ipinfo.io
- Email header analyzer (detects device/OS and SMTP path)
- Frontend UI (`web_ui.html`) with Analyze + Clear buttons

---

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/netsec404/TraceLinkGuard.git
   cd tracelinkguard

2. Create a virtual environment:
python -m venv venv
source venv/bin/activate   # Linux/Mac
.\venv\Scripts\activate    # Windows

3. Install dependencies:
pip install -r requirements.txt

▶️ Usage
Backend
Run the FastAPI server:
uvicorn tracelinkguard:app --reload --port 9000

Frontend
Serve the HTML UI:
python -m http.server 5500

Open in browser:
http://127.0.0.1:5500/web_ui.html

🧪 Testing- 
- Invalid input: abc123 → shows “Please enter a valid URL.”
- Safe domain: https://www.google.com → shows “Allow: Risk = Low” with Registrar + Domain Age.
- Suspicious domain: http://suspicious-example.biz → shows “Block: Risk = High” with reasons.
- Clear button: resets input and hides results.

link-guard/
├── tracelinkguard.py       # FastAPI backend
├── web_ui.html        # Frontend UI
├── requirements.txt   # Python dependencies
├── README.md          # Documentation
└── .gitignore         # Git ignore rules