# import re
# import tldextract
# from urllib.parse import urlparse

# shorteners = ["bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd", "buff.ly", "adf.ly", "bit.do"]

# def is_shortened(url):
#     try:
#         parsed = urlparse(url)
#         return parsed.netloc in shorteners
#     except:
#         return False

# def extract_features(url):
#     features = []
#     features.append(len(url))
#     features.append(url.count('.'))
#     features.append(url.count('-'))
#     features.append(url.count('@'))
#     features.append(1 if 'https' in url.lower() else 0)
#     features.append(1 if re.search(r'\d{1,3}(?:\.\d{1,3}){3}', url) else 0)
#     ext = tldextract.extract(url)
#     features.append(len(ext.subdomain.split('.')))
#     features.append(1 if is_shortened(url) else 0)
#     return features















# import re
# import socket
# import ssl
# import math
# import tldextract
# import requests
# import whois
# import dns.resolver
# from datetime import datetime
# from urllib.parse import urlparse
# from bs4 import BeautifulSoup

# # Common URL shorteners
# SHORTENERS = [
#     "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd", "buff.ly",
#     "adf.ly", "bit.do", "shorte.st", "bl.ink", "rebrand.ly", "lnkd.in", "s.id"
# ]

# # Suspicious TLDs often used for phishing
# SUSPICIOUS_TLDS = [
#     "xyz", "top", "tk", "ga", "cf", "gq", "ml", "pw", "bid", "vip", "loan",
#     "work", "club", "info", "click", "cam", "fit", "download"
# ]

# # Suspicious keywords (expanded)
# SUSPICIOUS_KEYWORDS = [
#     # General
#     "login", "signin", "verify", "secure", "account", "confirm", "update", "auth", "password",
#     # Finance
#     "bank", "paypal", "wallet", "crypto", "bitcoin", "payment", "invoice", "fund", "transfer", "upi",
#     # Scams
#     "free", "bonus", "win", "lottery", "reward", "offer", "prize", "claim", "gift", "promo",
#     # Brands (common phishing targets)
#     "facebook", "google", "apple", "microsoft", "amazon", "netflix", "instagram", "twitter",
#     "whatsapp", "linkedin", "snapchat", "telegram"
# ]

# # --- Utility Functions ---

# def is_shortened(url):
#     try:
#         parsed = urlparse(url)
#         return parsed.netloc.lower() in SHORTENERS
#     except:
#         return False


# def get_domain_info(domain):
#     """Return WHOIS and DNS-based information."""
#     info = {"domain_age": 0, "has_mx_record": 0, "has_txt_record": 0}
#     try:
#         w = whois.whois(domain)
#         creation_date = w.creation_date
#         if isinstance(creation_date, list):
#             creation_date = creation_date[0]
#         if creation_date:
#             info["domain_age"] = (datetime.now() - creation_date).days
#     except Exception:
#         pass

#     for record_type in ["MX", "TXT"]:
#         try:
#             dns.resolver.resolve(domain, record_type)
#             info[f"has_{record_type.lower()}_record"] = 1
#         except:
#             pass

#     return info


# def get_ssl_info(domain):
#     """Check SSL certificate validity and expiration."""
#     info = {"ssl_valid": 0, "ssl_days_left": 0}
#     try:
#         ctx = ssl.create_default_context()
#         with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
#             s.settimeout(3)
#             s.connect((domain, 443))
#             cert = s.getpeercert()
#             info["ssl_valid"] = 1
#             not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
#             info["ssl_days_left"] = (not_after - datetime.utcnow()).days
#     except Exception:
#         pass
#     return info


# def analyze_page_content(url):
#     """Analyze HTML for phishing indicators."""
#     features = {
#         "has_password_field": 0,
#         "external_links": 0,
#         "suspicious_forms": 0,
#         "hidden_iframes": 0,
#         "base64_usage": 0,
#         "js_redirect": 0
#     }
#     try:
#         res = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
#         if "text/html" not in res.headers.get("Content-Type", ""):
#             return features

#         soup = BeautifulSoup(res.text, "html.parser")

#         # Password field
#         if soup.find("input", {"type": "password"}):
#             features["has_password_field"] = 1

#         # External links
#         domain = tldextract.extract(url).registered_domain
#         all_links = [a.get("href") for a in soup.find_all("a", href=True)]
#         external_links = [l for l in all_links if l and domain not in l]
#         features["external_links"] = len(external_links)

#         # Suspicious forms
#         for form in soup.find_all("form"):
#             if any(k in (form.get("action") or "").lower() for k in SUSPICIOUS_KEYWORDS):
#                 features["suspicious_forms"] = 1
#                 break

#         # Hidden iframes (used for keyloggers)
#         iframes = soup.find_all("iframe", style=True)
#         for iframe in iframes:
#             style = iframe.get("style", "")
#             if "display:none" in style or "visibility:hidden" in style:
#                 features["hidden_iframes"] = 1

#         # Base64 encoded data (used to hide code)
#         if "base64" in res.text:
#             features["base64_usage"] = 1

#         # JS redirect
#         if re.search(r"window\.location|window\.open|document\.location", res.text):
#             features["js_redirect"] = 1

#     except Exception:
#         pass
#     return features


# def calculate_entropy(s):
#     """Calculate Shannon entropy (higher = more random/suspicious)."""
#     probabilities = [float(s.count(c)) / len(s) for c in set(s)]
#     return -sum(p * math.log(p, 2) for p in probabilities)


# def check_reputation_api(url):
#     """Stub for external reputation APIs like Google Safe Browsing or VirusTotal."""
#     # You can integrate:
#     # - Google Safe Browsing API
#     # - VirusTotal API
#     # - PhishTank API
#     return 0  # 0 = safe, 1 = flagged


# # --- Main Feature Extraction ---

# def extract_features(url):
#     features = []
#     try:
#         parsed = urlparse(url)
#         ext = tldextract.extract(url)
#         domain = ext.registered_domain.lower()
#         tld = ext.suffix.lower()
#         subdomain = ext.subdomain.lower()

#         # Lexical + Structural features
#         features.extend([
#             len(url),  # URL length
#             url.count('.'),
#             url.count('-'),
#             url.count('@'),
#             url.count('//'),
#             sum(c.isdigit() for c in url) / len(url),  # Digit ratio
#             sum(not c.isalnum() for c in url) / len(url),  # Symbol ratio
#             1 if "https" in url.lower() else 0,
#             1 if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", url) else 0,  # IP presence
#             len(ext.subdomain.split('.')),
#             1 if is_shortened(url) else 0,
#             sum(word in url.lower() for word in SUSPICIOUS_KEYWORDS),
#             1 if tld in SUSPICIOUS_TLDS else 0,
#             len(re.findall(r"%[0-9a-fA-F]{2}", url)),
#             calculate_entropy(url),
#             1 if "xn--" in url else 0,  # Punycode check
#             1 if any(k in subdomain for k in ["login", "secure", "update", "verify"]) else 0,  # Fake subdomain
#             1 if parsed.port and parsed.port not in [80, 443] else 0,  # Uncommon port
#         ])

#         # WHOIS / DNS / SSL
#         whois_info = get_domain_info(domain)
#         features.extend([
#             whois_info["domain_age"],
#             whois_info["has_mx_record"],
#             whois_info["has_txt_record"],
#         ])

#         ssl_info = get_ssl_info(domain)
#         features.extend([
#             ssl_info["ssl_valid"],
#             ssl_info["ssl_days_left"],
#         ])

#         # Page content
#         page_info = analyze_page_content(url)
#         features.extend([
#             page_info["has_password_field"],
#             page_info["external_links"],
#             page_info["suspicious_forms"],
#             page_info["hidden_iframes"],
#             page_info["base64_usage"],
#             page_info["js_redirect"],
#         ])

#         # Reputation
#         features.append(check_reputation_api(url))

#     except Exception as e:
#         print(f"[Feature Extraction Error] {e}")
#         features = [0] * 30

#     return features




































# import re
# import math
# import tldextract
# import socket
# import ssl
# import whois
# import dns.resolver
# from datetime import datetime
# from urllib.parse import urlparse

# # Common URL shorteners
# SHORTENERS = {"bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd", "buff.ly", "adf.ly", "bit.do"}

# # Suspicious TLDs and keywords
# SUSPICIOUS_TLDS = {"xyz","top","tk","ga","cf","gq","ml","pw","bid","vip","loan","work","club","info","click","cam","fit","download"}
# SUSPICIOUS_KEYWORDS = {
#     "login","signin","verify","secure","account","confirm","update","auth","password",
#     "bank","paypal","wallet","crypto","bitcoin","payment","invoice","fund","transfer","upi",
#     "free","bonus","win","lottery","reward","offer","prize","claim","gift","promo",
#     "facebook","google","apple","microsoft","amazon","netflix","instagram","twitter",
#     "whatsapp","linkedin","snapchat","telegram"
# }

# # --- Utility helpers ---------------------------------------------------------

# def safe_call(func, default=None):
#     """Safely call a function and return default on error."""
#     try:
#         return func()
#     except Exception:
#         return default

# def is_shortened(url):
#     try:
#         parsed = urlparse(url)
#         return parsed.netloc.lower() in SHORTENERS
#     except Exception:
#         return False

# def calculate_entropy(s):
#     """Calculate Shannon entropy."""
#     if not s:
#         return 0
#     probabilities = [float(s.count(c)) / len(s) for c in set(s)]
#     return -sum(p * math.log(p, 2) for p in probabilities)

# # --- Network-related feature getters (safe) ---------------------------------

# def get_domain_age(domain):
#     """Days since domain creation."""
#     def _inner():
#         w = whois.whois(domain)
#         cd = w.creation_date
#         if isinstance(cd, list):
#             cd = cd[0]
#         return (datetime.now() - cd).days if cd else 0
#     return safe_call(_inner, 0)

# def has_dns_record(domain, record_type):
#     def _inner():
#         dns.resolver.resolve(domain, record_type)
#         return 1
#     return safe_call(_inner, 0)

# def get_ssl_validity(domain):
#     """Returns tuple (valid, days_left)."""
#     def _inner():
#         ctx = ssl.create_default_context()
#         with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
#             s.settimeout(3)
#             s.connect((domain, 443))
#             cert = s.getpeercert()
#             not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
#             return (1, (not_after - datetime.utcnow()).days)
#     return safe_call(_inner, (0, 0))

# # --- Main feature extractor -------------------------------------------------

# def extract_features(url):
#     """Comprehensive feature extractor for phishing detection."""
#     try:
#         parsed = urlparse(url)
#         ext = tldextract.extract(url)
#         domain = ext.registered_domain.lower()
#         tld = ext.suffix.lower()
#         subdomain = ext.subdomain.lower()

#         # Lexical features
#         features = [
#             len(url),
#             url.count('.'),
#             url.count('-'),
#             url.count('@'),
#             url.count('//'),
#             sum(c.isdigit() for c in url) / len(url),
#             sum(not c.isalnum() for c in url) / len(url),
#             1 if url.lower().startswith("https") else 0,
#             1 if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", url) else 0,
#             len(ext.subdomain.split('.')),
#             1 if is_shortened(url) else 0,
#             sum(word in url.lower() for word in SUSPICIOUS_KEYWORDS),
#             1 if tld in SUSPICIOUS_TLDS else 0,
#             len(re.findall(r"%[0-9a-fA-F]{2}", url)),
#             calculate_entropy(url),
#             1 if "xn--" in url else 0,
#             1 if any(k in subdomain for k in ["login", "secure", "update", "verify"]) else 0,
#             1 if parsed.port and parsed.port not in [80, 443] else 0,
#         ]

#         # WHOIS + DNS + SSL (non-blocking safe calls)
#         domain_age = get_domain_age(domain)
#         mx_record = has_dns_record(domain, "MX")
#         txt_record = has_dns_record(domain, "TXT")
#         ssl_valid, ssl_days_left = get_ssl_validity(domain)

#         features.extend([
#             domain_age,
#             mx_record,
#             txt_record,
#             ssl_valid,
#             ssl_days_left,
#         ])

#         return features
#     except Exception as e:
#         print(f"[Feature extraction error for {url}] {e}")
#         return [0] * 24  # default vector length





















# import re
# import math
# import tldextract
# from urllib.parse import urlparse
# from datetime import datetime

# # --- Optional imports (safe import for production) ---
# try:
#     import socket, ssl, whois, dns.resolver
# except ImportError:
#     socket = ssl = whois = dns = None

# # --------------------- CONFIG --------------------------
# SHORTENERS = {
#     "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd",
#     "buff.ly", "adf.ly", "bit.do"
# }
# SUSPICIOUS_TLDS = {
#     "xyz","top","tk","ga","cf","gq","ml","pw","bid","vip",
#     "loan","work","club","info","click","cam","fit","download"
# }
# SUSPICIOUS_KEYWORDS = {
#     "login","signin","verify","secure","account","confirm","update","auth","password",
#     "bank","paypal","wallet","crypto","bitcoin","payment","invoice","fund","transfer","upi",
#     "free","bonus","win","lottery","reward","offer","prize","claim","gift","promo",
#     "facebook","google","apple","microsoft","amazon","netflix","instagram","twitter",
#     "whatsapp","linkedin","snapchat","telegram"
# }
# # -------------------------------------------------------

# def safe_call(func, default=None):
#     try:
#         return func()
#     except Exception:
#         return default

# def calculate_entropy(s):
#     """Shannon entropy."""
#     if not s:
#         return 0
#     probs = [s.count(c) / len(s) for c in set(s)]
#     return -sum(p * math.log(p, 2) for p in probs)

# def is_shortened(url):
#     try:
#         return urlparse(url).netloc.lower() in SHORTENERS
#     except Exception:
#         return False

# # ---- Fast, non-blocking placeholders (training mode) ----
# def get_domain_age(domain):
#     """Return domain age (days) — safe offline fallback."""
#     if not whois:
#         return 0
#     def _inner():
#         w = whois.whois(domain)
#         cd = w.creation_date
#         if isinstance(cd, list):
#             cd = cd[0]
#         return (datetime.now() - cd).days if cd else 0
#     return safe_call(_inner, 0)

# def has_dns_record(domain, record_type):
#     """Check DNS record existence (safe fallback)."""
#     if not dns:
#         return 0
#     def _inner():
#         dns.resolver.resolve(domain, record_type)
#         return 1
#     return safe_call(_inner, 0)

# def get_ssl_validity(domain):
#     """Return (valid, days_left)."""
#     if not ssl:
#         return (0, 0)
#     def _inner():
#         ctx = ssl.create_default_context()
#         with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
#             s.settimeout(3)
#             s.connect((domain, 443))
#             cert = s.getpeercert()
#             not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
#             return (1, (not_after - datetime.utcnow()).days)
#     return safe_call(_inner, (0, 0))

# # ---- MAIN FEATURE EXTRACTOR ----
# def extract_features(url):
#     """Return 24-D vector for a given URL."""
#     try:
#         parsed = urlparse(url)
#         ext = tldextract.extract(url)
#         domain = ext.registered_domain.lower()
#         tld = ext.suffix.lower()
#         subdomain = ext.subdomain.lower()

#         # --- Lexical Features ---
#         features = [
#             len(url),
#             url.count('.'),
#             url.count('-'),
#             url.count('@'),
#             url.count('//'),
#             sum(c.isdigit() for c in url) / len(url),
#             sum(not c.isalnum() for c in url) / len(url),
#             1 if url.lower().startswith("https") else 0,
#             1 if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", url) else 0,
#             len(ext.subdomain.split('.')),
#             1 if is_shortened(url) else 0,
#             sum(word in url.lower() for word in SUSPICIOUS_KEYWORDS),
#             1 if tld in SUSPICIOUS_TLDS else 0,
#             len(re.findall(r"%[0-9a-fA-F]{2}", url)),
#             calculate_entropy(url),
#             1 if "xn--" in url else 0,
#             1 if any(k in subdomain for k in ["login", "secure", "update", "verify"]) else 0,
#             1 if parsed.port and parsed.port not in [80, 443] else 0,
#         ]

#         # --- Network / Domain Info (safe) ---
#         domain_age = get_domain_age(domain)
#         mx_record = has_dns_record(domain, "MX")
#         txt_record = has_dns_record(domain, "TXT")
#         ssl_valid, ssl_days_left = get_ssl_validity(domain)

#         features.extend([
#             domain_age,
#             mx_record,
#             txt_record,
#             ssl_valid,
#             ssl_days_left,
#         ])

#         return features
#     except Exception as e:
#         print(f"[Feature extraction error for {url}] {e}")
#         return [0] * 24



















# src/features.py
import re
import math
import tldextract
from urllib.parse import urlparse

# --- Configuration ---
SHORTENERS = {"bit.ly","tinyurl.com","t.co","ow.ly","is.gd","buff.ly","adf.ly","bit.do","rebrand.ly","lnkd.in"}
SUSPICIOUS_TLDS = {"xyz","top","tk","ga","cf","gq","ml","pw","bid","vip","loan","work","club","info","click"}
SUSPICIOUS_KEYWORDS = {
    "login","signin","verify","secure","account","confirm","update","auth","password",
    "bank","paypal","wallet","crypto","bitcoin","payment","invoice","fund","transfer","upi",
    "free","bonus","win","lottery","reward","offer","prize","claim","gift","promo",
    "facebook","google","apple","microsoft","amazon","netflix","instagram","twitter",
    "whatsapp","linkedin","snapchat","telegram"
}

# --- Utility functions ---
def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c)/len(s) for c in set(s)]
    return -sum(p * math.log(p,2) for p in probs)

def is_shortened(url: str) -> int:
    try:
        host = urlparse(url).netloc.lower()
        return 1 if host in SHORTENERS else 0
    except Exception:
        return 0

# --- Main lexical feature extractor ---
def extract_lexical(url: str):
    """
    Fast-safe lexical+structural feature vector.
    Returns list of 18 features.
    """
    try:
        parsed = urlparse(url if url else "")
        ext = tldextract.extract(url if url else "")
        domain = ext.registered_domain or ""
        tld = ext.suffix or ""
        subdomain = ext.subdomain or ""

        url_len = len(url or "")
        dot_count = (url or "").count('.')
        dash_count = (url or "").count('-')
        at_count = (url or "").count('@')
        double_slash = (url or "").count('//')
        digit_ratio = sum(c.isdigit() for c in (url or "")) / (len(url or "") or 1)
        symbol_ratio = sum(not c.isalnum() for c in (url or "")) / (len(url or "") or 1)
        has_https = 1 if (parsed.scheme or "").lower() == "https" else 0
        has_ip = 1 if re.search(r'\d{1,3}(?:\.\d{1,3}){3}', url or "") else 0
        subdomain_depth = len(subdomain.split('.')) if subdomain else 0
        shortener = is_shortened(url)
        keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in (url or "").lower())
        suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
        encoded_chars = len(re.findall(r"%[0-9a-fA-F]{2}", url or ""))
        entropy = calculate_entropy(url or "")
        punycode = 1 if "xn--" in (url or "").lower() else 0
        fake_subdomain = 1 if any(k in subdomain.lower() for k in ("login","secure","update","verify")) else 0
        uncommon_port = 1 if parsed.port and parsed.port not in (80,443) else 0

        return [
            url_len, dot_count, dash_count, at_count, double_slash,
            digit_ratio, symbol_ratio, has_https, has_ip, subdomain_depth,
            shortener, keyword_count, suspicious_tld, encoded_chars, entropy,
            punycode, fake_subdomain, uncommon_port
        ]
    except Exception:
        return [0]*18

# Make backward-compatible name
extract_features = extract_lexical
