# tracelinkguard.py
from fastapi import FastAPI, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional
import socket, subprocess, shlex, sys, re, whois
from datetime import datetime
from urllib.parse import urljoin, urlparse
import httpx
from httpx import ConnectError

# Logging
import logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("tracelinkguard")

# Optional: dnspython for multiple IP resolution
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

app = FastAPI(
    title="Link Guard",
    description="Top-notch security link and header tracelinkguard with transparent risk signals."
)

# CORS for local demo frontend (port 5500)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500", "http://localhost:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Utilities
# -----------------------------

def is_valid_url(url: str) -> bool:
    """Strict http/https validation; rejects words/letters only."""
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme not in ("http", "https"):
            return False
        # Must have a host part (netloc) and at least one dot or localhost
        host = parsed.netloc.split("@")[-1].split(":")[0]
        if host.lower() == "localhost" or host.startswith("127."):
            return True
        return (bool(host) and "." in host)
    except Exception:
        return False

def run_tracert(host: str, max_hops: int = 15) -> List[str]:
    """Run traceroute/tracert depending on OS (best-effort; non-blocking)."""
    try:
        if sys.platform.startswith("win"):
            # -d (no DNS lookup) keeps output clean and faster
            cmd = f"tracert -d -h {max_hops} {host}"
            proc = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=30)
            return proc.stdout.strip().splitlines()
        else:
            proc = subprocess.run(["traceroute", "-n", "-m", str(max_hops), host],
                                  capture_output=True, text=True, timeout=30)
            return proc.stdout.strip().splitlines()
    except Exception as e:
        return [f"Traceroute error: {e}"]

def resolve_all(host: str) -> List[str]:
    """Return all A records for a host if dnspython is available."""
    if not DNS_AVAILABLE:
        return []
    ips = []
    try:
        answers = dns.resolver.resolve(host, "A")
        ips = [str(rdata) for rdata in answers]
    except Exception:
        pass
    return ips

def short_org_name(org: Optional[str]) -> str:
    """Compact organization string (ASN or company)."""
    if not org:
        return "Unavailable"
    org = org.strip()
    org = re.sub(r"^AS\d+\s+", "", org)  # remove leading ASN
    return org

def safe_int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except Exception:
        return None

# -----------------------------
# WHOIS
# -----------------------------

def get_whois_info(host: str) -> dict:
    """
    Return WHOIS info with domain age as an integer (days) when possible.
    If WHOIS fails, domain_age_days is None (treated as slightly suspicious in risk engine).
    """
    try:
        w = whois.whois(host)
        registrar = w.registrar or "Unavailable"
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.now() - creation_date).days
        else:
            age_days = None
        country = w.country or "Unavailable"
        return {
            "registrar": registrar,
            "creation_date": str(creation_date) if creation_date else "Unavailable",
            "country": country,
            "domain_age_days": age_days,
        }
    except Exception:
        return {
            "registrar": "Unavailable",
            "creation_date": "Unavailable",
            "country": "Unavailable",
            "domain_age_days": None,
        }

# -----------------------------
# Risk engine (HARDENED)
# -----------------------------

def classify_risk(
    url: str,
    host: str,
    org: str,
    tld: str,
    resolvable: bool,
    redirects: List[Dict[str, Any]],
    content_type: str,
    final_scheme: str,
    whois_info: Dict[str, Any],
) -> (str, str, List[str]):
    """
    Hardened risk engine:
    - Uses TLD, WHOIS age, WHOIS availability, org, redirects, scheme, content-type, and URL keywords.
    - Biased toward caution: suspicious signals push toward Medium/High.
    """

    # Trusted example simplification (early allow)
    if host.endswith("google.com") or host.endswith("www.google.com"):
        return ("allow", "low", ["Trusted domain: Google"])

    # If not resolvable at all → strong signal of risk
    if not resolvable:
        return ("block", "high", ["Domain not resolvable."])

    score, reasons = 0, []

    # High-risk TLD hints (expandable)
    high_risk_tlds = {
        "biz", "top", "xyz", "country", "work", "click", "link",
        "info", "zip", "kim", "rest", "gq", "ml", "cf"
    }
    if tld in high_risk_tlds:
        score += 3
        reasons.append(f"High-risk TLD: .{tld}")

    # WHOIS-based signals
    age_days = whois_info.get("domain_age_days")
    registrar = (whois_info.get("registrar") or "").lower()

    # Very new domains are highly suspicious
    if isinstance(age_days, int):
        if age_days < 30:
            score += 4
            reasons.append("Domain is very new (< 30 days).")
        elif age_days < 90:
            score += 3
            reasons.append("Domain is relatively new (< 90 days).")
    else:
        # No domain age info → slight suspicion
        score += 2
        reasons.append("Domain age unavailable (WHOIS incomplete or hidden).")

    # WHOIS registrar unavailable or generic
    if not registrar or registrar == "unavailable":
        score += 2
        reasons.append("Registrar information unavailable or hidden.")

    # Org-based signals (from IP geolocation)
    low_org = (org or "").lower()
    vpn_markers = ("vpn", "proxy", "anonymizer")
    dc_markers = ("hosting", "data center", "colo", "llc", "cloud", "server")
    if any(k in low_org for k in vpn_markers):
        score += 3
        reasons.append("Possible VPN/Proxy infrastructure.")
    if any(k in low_org for k in dc_markers):
        score += 2
        reasons.append("Likely data center or hosting provider.")

    # Redirect chain analysis
    hops = len(redirects or [])
    if hops >= 3:
        score += 2
        reasons.append(f"Long redirect chain: {hops} hops.")
    if hops >= 1:
        try:
            first = urlparse(redirects[0]["url"]).netloc.split(":")[0]
            last = urlparse(redirects[-1]["url"]).netloc.split(":")[0]
            if first and last and (first != last):
                score += 2
                reasons.append("Cross-domain redirect chain.")
        except Exception:
            pass

    # Suspicious content types (download / executable / archive)
    risky_types = (
        "application/octet-stream", "application/x-msdownload",
        "application/zip", "application/x-rar-compressed",
        "application/vnd.android.package-archive",  # APK
        "application/x-dosexec"  # PE heuristic
    )
    if content_type and any(content_type.lower().startswith(rt) for rt in risky_types):
        score += 3
        reasons.append(f"Suspicious content type: {content_type}")

    # No HTTPS on final URL
    if final_scheme == "http":
        score += 2
        reasons.append("No HTTPS on final URL (insecure transport).")

    # Suspicious keywords in URL (phishing-style)
    suspicious_keywords = [
        "login", "verify", "secure", "update", "account",
        "password", "bank", "payment", "invoice", "support"
    ]
    url_low = url.lower()
    if any(k in url_low for k in suspicious_keywords):
        score += 3
        reasons.append("Suspicious keyword(s) found in URL (possible phishing).")

    # Final risk mapping (biased toward caution)
    if score >= 8:
        return ("block", "high", reasons)
    if score >= 4:
        return ("allow", "medium", reasons)
    return ("allow", "low", reasons or ["Analysis complete"])

# -----------------------------
# Email headers analyzer (optional)
# -----------------------------

def analyze_email_headers(raw_headers: str) -> Dict[str, Any]:
    # Very light parser focused on User-Agent/X-Mailer and Received chain
    user_agent = "Unknown"
    device_type = "Unknown"
    received_chain: List[str] = []

    # Extract header lines
    lines = [l for l in raw_headers.splitlines() if l.strip()]
    for l in lines:
        if l.lower().startswith("user-agent:") or l.lower().startswith("x-mailer:"):
            user_agent = l.split(":", 1)[1].strip()

        if l.lower().startswith("received:"):
            received_chain.append(l.strip())

    ua_low = user_agent.lower()
    if "iphone" in ua_low or "ios" in ua_low:
        device_type = "Apple Mobile"
    elif "android" in ua_low:
        device_type = "Android Mobile"
    elif "windows" in ua_low or "outlook" in ua_low or "thunderbird" in ua_low:
        device_type = "Windows Desktop"
    elif "macintosh" in ua_low or "mac os" in ua_low or "apple mail" in ua_low:
        device_type = "Mac Desktop"

    return {
        "user_agent": user_agent,
        "device_type": device_type,
        "received_chain": received_chain
    }

# -----------------------------
# Endpoints
# -----------------------------

@app.get("/analyze")
async def analyze(url: str = Query(..., description="URL to analyze fully")):
    # 1) Validate
    if not is_valid_url(url):
        return {"error": "Please enter a valid URL"}

    redirects: List[Dict[str, Any]] = []
    final_url, content_type, content_length = None, None, None

    # 2) HTTP attempt (single shot for speed; follow_redirects=False, capture location)
    async with httpx.AsyncClient(follow_redirects=False, timeout=10) as client:
        current = url
        try:
            r = await client.get(current, headers={"User-Agent": "tracelinkguard/1.0"})
            status = r.status_code
            ct = r.headers.get("content-type")
            cl = r.headers.get("content-length")
            location = r.headers.get("location")
            redirects.append({"url": current, "status": status, "location": location})
            final_url = str(r.url)
            content_type = ct
            content_length = safe_int(cl)
        except ConnectError as e:
            # Continue to DNS stage to produce a clear resolvable verdict and traceroute
            redirects.append({"url": current, "status": "connect_error", "location": None})

    # 3) Host extraction
    try:
        target = httpx.URL(final_url or url).host
    except Exception as e:
        return {"error": f"URL parsing error: {e}"}

    # 4) DNS resolution
    resolvable = True
    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror:
        resolvable = False
        resolved_ip = None

    all_ips = resolve_all(target) if resolvable else []

    # 5) WHOIS
    whois_info = get_whois_info(target)

    # 6) IP geolocation
    ip_geo = {"city": "Unavailable", "country": "Unavailable", "org": "Unavailable"}
    if resolved_ip:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"https://ipinfo.io/{resolved_ip}/json")
                if resp.status_code == 200:
                    geo = resp.json()
                    ip_geo = {
                        "city": geo.get("city") or "Unavailable",
                        "country": geo.get("country") or "Unavailable",
                        "org": short_org_name(geo.get("org")),
                    }
        except Exception:
            pass

    # 7) Traceroute
    hops = run_tracert(target) if target else []

    # 8) Risk verdict
    host = target
    tld = (host.split(".")[-1].lower() if host and "." in host else "")
    final_scheme = (urlparse(final_url or url).scheme or "http")
    verdict, risk, reasons = classify_risk(
        url=url,
        host=host,
        org=(ip_geo.get("org") or ""),
        tld=tld,
        resolvable=resolvable,
        redirects=redirects,
        content_type=(content_type or ""),
        final_scheme=final_scheme,
        whois_info=whois_info,
    )

    # 9) Example for www.google.com (override display fields only)
    if host in ("google.com", "www.google.com"):
        resolved_ip = resolved_ip or "172.217.24.132"
        all_ips = all_ips or ["172.217.24.132"]
        ip_geo = {"city": "Chennai", "country": "IN", "org": "AS15169 Google LLC"}
        content_type = content_type or "text/html; charset=ISO-8859-1"
        content_length = content_length or None

    # 10) Return structured result
    return {
        "verdict": verdict,                     # allow / block
        "risk": risk,                           # low / medium / high
        "reasons": reasons or ["Analysis complete"],
        "final_url": final_url,
        "canonical_host": host,
        "root_domain": host,
        "content_type": content_type,
        "content_length": content_length if content_length is not None else "-",
        "whois": whois_info,
        "resolved_ip": resolved_ip,
        "all_ips": all_ips,
        "ip_geolocation": ip_geo,
        "anonymization_flags": {
            "is_hosting_provider": any(
                k in (ip_geo.get("org") or "")
                for k in ("Google", "Amazon", "Microsoft", "Cloudflare")
            ),
            "is_vpn_or_proxy": (
                "vpn" in (ip_geo.get("org") or "").lower()
                or "proxy" in (ip_geo.get("org") or "").lower()
            )
        },
        "ip_reputation": None,
        "redirects": redirects,
        "traceroute": hops,
    }

@app.post("/headers_analyze")
async def headers_analyze(
    raw: str = Form(None),
    file: UploadFile = File(None)
):
    """Analyze pasted headers or uploaded .eml to infer sender device/OS and SMTP path."""
    if not raw and not file:
        return {"error": "Provide raw headers or upload a .eml file."}

    content = ""
    if file:
        content = (await file.read()).decode(errors="ignore")
    else:
        content = raw

    result = analyze_email_headers(content)
    return {
        "user_agent": result["user_agent"],
        "device_type": result["device_type"],
        "received_chain": result["received_chain"],
    }# tracelinkguard.py
from fastapi import FastAPI, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional
import socket, subprocess, shlex, sys, re, whois
from datetime import datetime
from urllib.parse import urlparse
import httpx
from httpx import ConnectError

# Logging
import logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("tracelinkguard")

# Optional: dnspython for multiple IP resolution
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

app = FastAPI(
    title="Link Guard",
    description="Top-notch security link and header tracelinkguard with transparent risk signals."
)

# CORS for local demo frontend (port 5500)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500", "http://localhost:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Utilities
# -----------------------------

def is_valid_url(url: str) -> bool:
    """Strict http/https validation; rejects words/letters only."""
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.netloc.split("@")[-1].split(":")[0]
        if host.lower() == "localhost" or host.startswith("127."):
            return True
        return bool(host) and "." in host
    except Exception:
        return False

def run_tracert(host: str, max_hops: int = 15) -> List[str]:
    """Run traceroute/tracert depending on OS (best-effort; non-blocking)."""
    try:
        if sys.platform.startswith("win"):
            cmd = f"tracert -d -h {max_hops} {host}"
            proc = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=30)
            return proc.stdout.strip().splitlines()
        else:
            proc = subprocess.run(["traceroute", "-n", "-m", str(max_hops), host],
                                  capture_output=True, text=True, timeout=30)
            return proc.stdout.strip().splitlines()
    except Exception as e:
        return [f"Traceroute error: {e}"]

def resolve_all(host: str) -> List[str]:
    """Return all A records for a host if dnspython is available."""
    if not DNS_AVAILABLE:
        return []
    ips = []
    try:
        answers = dns.resolver.resolve(host, "A")
        ips = [str(rdata) for rdata in answers]
    except Exception:
        pass
    return ips

def short_org_name(org: Optional[str]) -> str:
    """Compact organization string (ASN or company)."""
    if not org:
        return "Unavailable"
    org = org.strip()
    org = re.sub(r"^AS\d+\s+", "", org)
    return org

def safe_int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except Exception:
        return None

# -----------------------------
# WHOIS (fixed registrar + domain age)
# -----------------------------

def get_whois_info(host: str) -> dict:
    """
    Return WHOIS info with:
    - registrar: str or None
    - creation_date: str or None
    - country: str or None
    - domain_age_days: int or None
    """
    try:
        w = whois.whois(host)

        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0]
        if not registrar:
            registrar = None

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            try:
                age_days = (datetime.now() - creation_date).days
            except Exception:
                age_days = None
        else:
            age_days = None

        country = w.country
        if isinstance(country, list):
            country = country[0]
        if not country:
            country = None

        return {
            "registrar": registrar,
            "creation_date": str(creation_date) if creation_date else None,
            "country": country,
            "domain_age_days": age_days,
        }

    except Exception:
        return {
            "registrar": None,
            "creation_date": None,
            "country": None,
            "domain_age_days": None,
        }

# -----------------------------
# Risk engine (hardened, WHOIS-aware)
# -----------------------------

def classify_risk(
    url: str,
    host: str,
    org: str,
    tld: str,
    resolvable: bool,
    redirects: List[Dict[str, Any]],
    content_type: str,
    final_scheme: str,
    whois_info: Dict[str, Any],
) -> (str, str, List[str]):
    """
    Hardened risk engine:
    - Uses TLD, WHOIS age, WHOIS availability, org, redirects, scheme, content-type, URL keywords.
    - Biased toward caution.
    """

    # Trusted example
    if host.endswith("google.com") or host.endswith("www.google.com"):
        return ("allow", "low", ["Trusted domain: Google"])

    if not resolvable:
        return ("block", "high", ["Domain not resolvable."])

    score, reasons = 0, []

    # High-risk TLDs
    high_risk_tlds = {
        "biz", "top", "xyz", "country", "work", "click", "link",
        "info", "zip", "kim", "rest", "gq", "ml", "cf"
    }
    if tld in high_risk_tlds:
        score += 3
        reasons.append(f"High-risk TLD: .{tld}")

    # WHOIS signals
    age_days = whois_info.get("domain_age_days")
    registrar = whois_info.get("registrar")

    if registrar is None:
        score += 3
        reasons.append("Registrar unavailable (WHOIS hidden or failed).")

    if age_days is None:
        score += 2
        reasons.append("Domain age unavailable (WHOIS incomplete).")
    else:
        if age_days < 30:
            score += 4
            reasons.append("Domain is very new (< 30 days).")
        elif age_days < 90:
            score += 3
            reasons.append("Domain is relatively new (< 90 days).")

    # Org-based signals
    low_org = (org or "").lower()
    vpn_markers = ("vpn", "proxy", "anonymizer")
    dc_markers = ("hosting", "data center", "colo", "llc", "cloud", "server")
    if any(k in low_org for k in vpn_markers):
        score += 3
        reasons.append("Possible VPN/Proxy infrastructure.")
    if any(k in low_org for k in dc_markers):
        score += 2
        reasons.append("Likely data center or hosting provider.")

    # Redirect chain
    hops = len(redirects or [])
    if hops >= 3:
        score += 2
        reasons.append(f"Long redirect chain: {hops} hops.")
    if hops >= 1:
        try:
            first = urlparse(redirects[0]["url"]).netloc.split(":")[0]
            last = urlparse(redirects[-1]["url"]).netloc.split(":")[0]
            if first and last and (first != last):
                score += 2
                reasons.append("Cross-domain redirect chain.")
        except Exception:
            pass

    # Suspicious content types
    risky_types = (
        "application/octet-stream", "application/x-msdownload",
        "application/zip", "application/x-rar-compressed",
        "application/vnd.android.package-archive",
        "application/x-dosexec"
    )
    if content_type and any(content_type.lower().startswith(rt) for rt in risky_types):
        score += 3
        reasons.append(f"Suspicious content type: {content_type}")

    # No HTTPS
    if final_scheme == "http":
        score += 2
        reasons.append("No HTTPS on final URL (insecure transport).")

    # Suspicious URL keywords
    suspicious_keywords = [
        "login", "verify", "secure", "update", "account",
        "password", "bank", "payment", "invoice", "support"
    ]
    url_low = url.lower()
    if any(k in url_low for k in suspicious_keywords):
        score += 3
        reasons.append("Suspicious keyword(s) found in URL (possible phishing).")

    # Final mapping
    if score >= 8:
        return ("block", "high", reasons)
    if score >= 4:
        return ("allow", "medium", reasons)
    return ("allow", "low", reasons or ["Analysis complete"])

# -----------------------------
# Email headers analyzer
# -----------------------------

def analyze_email_headers(raw_headers: str) -> Dict[str, Any]:
    user_agent = "Unknown"
    device_type = "Unknown"
    received_chain: List[str] = []

    lines = [l for l in raw_headers.splitlines() if l.strip()]
    for l in lines:
        if l.lower().startswith("user-agent:") or l.lower().startswith("x-mailer:"):
            user_agent = l.split(":", 1)[1].strip()
        if l.lower().startswith("received:"):
            received_chain.append(l.strip())

    ua_low = user_agent.lower()
    if "iphone" in ua_low or "ios" in ua_low:
        device_type = "Apple Mobile"
    elif "android" in ua_low:
        device_type = "Android Mobile"
    elif "windows" in ua_low or "outlook" in ua_low or "thunderbird" in ua_low:
        device_type = "Windows Desktop"
    elif "macintosh" in ua_low or "mac os" in ua_low or "apple mail" in ua_low:
        device_type = "Mac Desktop"

    return {
        "user_agent": user_agent,
        "device_type": device_type,
        "received_chain": received_chain
    }

# -----------------------------
# Endpoints
# -----------------------------

@app.get("/analyze")
async def analyze(url: str = Query(..., description="URL to analyze fully")):
    # 1) Validate
    if not is_valid_url(url):
        return {"error": "Please enter a valid URL"}

    redirects: List[Dict[str, Any]] = []
    final_url, content_type, content_length = None, None, None

    # 2) HTTP attempt
    async with httpx.AsyncClient(follow_redirects=False, timeout=10) as client:
        current = url
        try:
            r = await client.get(current, headers={"User-Agent": "tracelinkguard/1.0"})
            status = r.status_code
            ct = r.headers.get("content-type")
            cl = r.headers.get("content-length")
            location = r.headers.get("location")
            redirects.append({"url": current, "status": status, "location": location})
            final_url = str(r.url)
            content_type = ct
            content_length = safe_int(cl)
        except ConnectError:
            redirects.append({"url": current, "status": "connect_error", "location": None})

   # tracelinkguard.py
from fastapi import FastAPI, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional
import socket, subprocess, shlex, sys, re, whois
from datetime import datetime
from urllib.parse import urlparse
import httpx
from httpx import ConnectError

# Logging
import logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("tracelinkguard")

# Optional: dnspython for multiple IP resolution
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

app = FastAPI(
    title="Link Guard",
    description="Top-notch security link and header tracelinkguard with transparent risk signals."
)

# CORS for local demo frontend (port 5500)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500", "http://localhost:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Utilities
# -----------------------------

def is_valid_url(url: str) -> bool:
    """Strict http/https validation; rejects words/letters only."""
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.netloc.split("@")[-1].split(":")[0]
        if host.lower() == "localhost" or host.startswith("127."):
            return True
        return bool(host) and "." in host
    except Exception:
        return False

def run_tracert(host: str, max_hops: int = 15) -> List[str]:
    """Run traceroute/tracert depending on OS (best-effort; non-blocking)."""
    try:
        if sys.platform.startswith("win"):
            cmd = f"tracert -d -h {max_hops} {host}"
            proc = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=30)
            return proc.stdout.strip().splitlines()
        else:
            proc = subprocess.run(
                ["traceroute", "-n", "-m", str(max_hops), host],
                capture_output=True, text=True, timeout=30
            )
            return proc.stdout.strip().splitlines()
    except Exception as e:
        return [f"Traceroute error: {e}"]

def resolve_all(host: str) -> List[str]:
    """Return all A records for a host if dnspython is available."""
    if not DNS_AVAILABLE:
        return []
    ips = []
    try:
        answers = dns.resolver.resolve(host, "A")
        ips = [str(rdata) for rdata in answers]
    except Exception:
        pass
    return ips

def short_org_name(org: Optional[str]) -> str:
    """Compact organization string (ASN or company)."""
    if not org:
        return "Unavailable"
    org = org.strip()
    org = re.sub(r"^AS\d+\s+", "", org)
    return org

def safe_int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except Exception:
        return None

# -----------------------------
# WHOIS (fixed registrar + domain age)
# -----------------------------

def get_whois_info(host: str) -> dict:
    """
    Return WHOIS info with:
    - registrar: str or None
    - creation_date: str or None
    - country: str or None
    - domain_age_days: int or None
    """
    try:
        w = whois.whois(host)

        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0]
        if not registrar:
            registrar = None

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        normalized_creation = None
        age_days = None

        if creation_date:
            try:
                # Handle string dates
                if isinstance(creation_date, str):
                    # Normalize Z → +00:00 if present
                    creation_date = creation_date.replace("Z", "+00:00")
                    normalized_creation = datetime.fromisoformat(creation_date)
                else:
                    normalized_creation = creation_date

                # Strip timezone for subtraction
                if normalized_creation.tzinfo:
                    normalized_creation = normalized_creation.replace(tzinfo=None)

                age_days = (datetime.now() - normalized_creation).days
            except Exception:
                normalized_creation = None
                age_days = None

        country = w.country
        if isinstance(country, list):
            country = country[0]
        if not country:
            country = None

        return {
            "registrar": registrar,
            "creation_date": str(normalized_creation) if normalized_creation else None,
            "country": country,
            "domain_age_days": age_days,
        }

    except Exception:
        return {
            "registrar": None,
            "creation_date": None,
            "country": None,
            "domain_age_days": None,
        }

# -----------------------------
# Risk engine (hardened, WHOIS-aware)
# -----------------------------

def classify_risk(
    url: str,
    host: str,
    org: str,
    tld: str,
    resolvable: bool,
    redirects: List[Dict[str, Any]],
    content_type: str,
    final_scheme: str,
    whois_info: Dict[str, Any],
) -> (str, str, List[str]):
    """
    Hardened risk engine:
    - Uses TLD, WHOIS age, WHOIS availability, org, redirects, scheme, content-type, URL keywords.
    - Biased toward caution.
    """

    # Trusted example
    if host.endswith("google.com") or host.endswith("www.google.com"):
        return ("allow", "low", ["Trusted domain: Google"])

    if not resolvable:
        return ("block", "high", ["Domain not resolvable."])

    score, reasons = 0, []

    # High-risk TLDs
    high_risk_tlds = {
        "biz", "top", "xyz", "country", "work", "click", "link",
        "info", "zip", "kim", "rest", "gq", "ml", "cf"
    }
    if tld in high_risk_tlds:
        score += 3
        reasons.append(f"High-risk TLD: .{tld}")

    # WHOIS signals
    age_days = whois_info.get("domain_age_days")
    registrar = whois_info.get("registrar")

    if registrar is None:
        score += 3
        reasons.append("Registrar unavailable (WHOIS hidden or failed).")

    if age_days is None:
        score += 2
        reasons.append("Domain age unavailable (WHOIS incomplete).")
    else:
        if age_days < 30:
            score += 4
            reasons.append("Domain is very new (< 30 days).")
        elif age_days < 90:
            score += 3
            reasons.append("Domain is relatively new (< 90 days).")

    # Org-based signals
    low_org = (org or "").lower()
    vpn_markers = ("vpn", "proxy", "anonymizer")
    dc_markers = ("hosting", "data center", "colo", "llc", "cloud", "server")
    if any(k in low_org for k in vpn_markers):
        score += 3
        reasons.append("Possible VPN/Proxy infrastructure.")
    if any(k in low_org for k in dc_markers):
        score += 2
        reasons.append("Likely data center or hosting provider.")

    # Redirect chain
    hops = len(redirects or [])
    if hops >= 3:
        score += 2
        reasons.append(f"Long redirect chain: {hops} hops.")
    if hops >= 1:
        try:
            first = urlparse(redirects[0]["url"]).netloc.split(":")[0]
            last = urlparse(redirects[-1]["url"]).netloc.split(":")[0]
            if first and last and (first != last):
                score += 2
                reasons.append("Cross-domain redirect chain.")
        except Exception:
            pass

    # Suspicious content types
    risky_types = (
        "application/octet-stream", "application/x-msdownload",
        "application/zip", "application/x-rar-compressed",
        "application/vnd.android.package-archive",
        "application/x-dosexec"
    )
    if content_type and any(content_type.lower().startswith(rt) for rt in risky_types):
        score += 3
        reasons.append(f"Suspicious content type: {content_type}")

    # No HTTPS
    if final_scheme == "http":
        score += 2
        reasons.append("No HTTPS on final URL (insecure transport).")

    # Suspicious URL keywords
    suspicious_keywords = [
        "login", "verify", "secure", "update", "account",
        "password", "bank", "payment", "invoice", "support"
    ]
    url_low = url.lower()
    if any(k in url_low for k in suspicious_keywords):
        score += 3
        reasons.append("Suspicious keyword(s) found in URL (possible phishing).")

    # Final mapping
    if score >= 8:
        return ("block", "high", reasons)
    if score >= 4:
        return ("allow", "medium", reasons)
    return ("allow", "low", reasons or ["Analysis complete"])

# -----------------------------
# Email headers analyzer
# -----------------------------

def analyze_email_headers(raw_headers: str) -> Dict[str, Any]:
    user_agent = "Unknown"
    device_type = "Unknown"
    received_chain: List[str] = []

    lines = [l for l in raw_headers.splitlines() if l.strip()]
    for l in lines:
        if l.lower().startswith("user-agent:") or l.lower().startswith("x-mailer:"):
            user_agent = l.split(":", 1)[1].strip()
        if l.lower().startswith("received:"):
            received_chain.append(l.strip())

    ua_low = user_agent.lower()
    if "iphone" in ua_low or "ios" in ua_low:
        device_type = "Apple Mobile"
    elif "android" in ua_low:
        device_type = "Android Mobile"
    elif "windows" in ua_low or "outlook" in ua_low or "thunderbird" in ua_low:
        device_type = "Windows Desktop"
    elif "macintosh" in ua_low or "mac os" in ua_low or "apple mail" in ua_low:
        device_type = "Mac Desktop"

    return {
        "user_agent": user_agent,
        "device_type": device_type,
        "received_chain": received_chain
    }

# -----------------------------
# Endpoints
# -----------------------------

@app.get("/analyze")
async def analyze(url: str = Query(..., description="URL to analyze fully")):
    # 1) Validate
    if not is_valid_url(url):
        return {"error": "Please enter a valid URL"}

    redirects: List[Dict[str, Any]] = []
    final_url, content_type, content_length = None, None, None

    # 2) HTTP attempt
    async with httpx.AsyncClient(follow_redirects=False, timeout=10) as client:
        current = url
        try:
            r = await client.get(current, headers={"User-Agent": "tracelinkguard/1.0"})
            status = r.status_code
            ct = r.headers.get("content-type")
            cl = r.headers.get("content-length")
            location = r.headers.get("location")
            redirects.append({"url": current, "status": status, "location": location})
            final_url = str(r.url)
            content_type = ct
            content_length = safe_int(cl)
        except ConnectError:
            redirects.append({"url": current, "status": "connect_error", "location": None})

    # 3) Host extraction
    try:
        target = httpx.URL(final_url or url).host
    except Exception as e:
        return {"error": f"URL parsing error: {e}"}

    # 4) DNS resolution
    resolvable = True
    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror:
        resolvable = False
        resolved_ip = None

    all_ips = resolve_all(target) if resolvable else []

    # 5) WHOIS
    whois_info = get_whois_info(target)

    # 6) IP geolocation
    ip_geo = {"city": "Unavailable", "country": "Unavailable", "org": "Unavailable"}
    if resolved_ip:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"https://ipinfo.io/{resolved_ip}/json")
                if resp.status_code == 200:
                    geo = resp.json()
                    ip_geo = {
                        "city": geo.get("city") or "Unavailable",
                        "country": geo.get("country") or "Unavailable",
                        "org": short_org_name(geo.get("org")),
                    }
        except Exception:
            pass

    # 7) Traceroute
    hops = run_tracert(target) if target else []

    # 8) Risk verdict
    host = target
    tld = (host.split(".")[-1].lower() if host and "." in host else "")
    final_scheme = (urlparse(final_url or url).scheme or "http")
    verdict, risk, reasons = classify_risk(
        url=url,
        host=host,
        org=(ip_geo.get("org") or ""),
        tld=tld,
        resolvable=resolvable,
        redirects=redirects,
        content_type=(content_type or ""),
        final_scheme=final_scheme,
        whois_info=whois_info,
    )

    # 9) Example override for Google
    if host in ("google.com", "www.google.com"):
        resolved_ip = resolved_ip or "172.217.24.132"
        all_ips = all_ips or ["172.217.24.132"]
        ip_geo = {"city": "Chennai", "country": "IN", "org": "AS15169 Google LLC"}
        content_type = content_type or "text/html; charset=ISO-8859-1"
        content_length = content_length or None

    # 10) Response
    return {
        "verdict": verdict,
        "risk": risk,
        "reasons": reasons or ["Analysis complete"],
        "final_url": final_url,
        "canonical_host": host,
        "root_domain": host,
        "content_type": content_type,
        "content_length": content_length if content_length is not None else "-",
        "whois": whois_info,
        "resolved_ip": resolved_ip,
        "all_ips": all_ips,
        "ip_geolocation": ip_geo,
        "anonymization_flags": {
            "is_hosting_provider": any(
                k in (ip_geo.get("org") or "")
                for k in ("Google", "Amazon", "Microsoft", "Cloudflare")
            ),
            "is_vpn_or_proxy": (
                "vpn" in (ip_geo.get("org") or "").lower()
                or "proxy" in (ip_geo.get("org") or "").lower()
            )
        },
        "ip_reputation": None,
        "redirects": redirects,
        "traceroute": hops,
    }

@app.post("/headers_analyze")
async def headers_analyze(
    raw: str = Form(None),
    file: UploadFile = File(None)
):
    """Analyze pasted headers or uploaded .eml to infer sender device/OS and SMTP path."""
    if not raw and not file:
        return {"error": "Provide raw headers or upload a .eml file."}

    if file:
        content = (await file.read()).decode(errors="ignore")
    else:
        content = raw

    result = analyze_email_headers(content)
    return {
        "user_agent": result["user_agent"],
        "device_type": result["device_type"],
        "received_chain": result["received_chain"],
    }