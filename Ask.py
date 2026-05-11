import os
import re
import json
import requests
import subprocess
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from collections import defaultdict

PAYLOAD_INDEX = defaultdict(list)

# =========================
# CONFIG
# =========================
BASE_DIR = "C:/Users/GUEST1/.openclaw/workspace/docs"
CHUNK_SIZE = 800
MAX_RESULTS = 5
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5:7b"

# =========================
# FUZZ PAYLOADS
# =========================


DEFAULT_PAYLOADS = [
    "'",
    '"',
    "1 OR 1=1",
    "' OR '1'='1",
    "<script>alert(1)</script>",
    "../../../../etc/passwd",
    "../../windows/win.ini",
    "999999999",
    "%27",
]

# =========================
# URL HELPERS
# =========================
def replace_param(url, param, value):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]

    new_query = urlencode(qs, doseq=True)

    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))

def load_payloads():
    payloads = set(DEFAULT_PAYLOADS)

    path = "collector_data/intel/payload_bank.json"
    
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for category in data.get("payloads", {}):
                for item in data["payloads"][category]:
                    payloads.add(item)

        except Exception as e:
            print("Payload intel load failed:", e)

    return list(payloads)
FUZZ_PAYLOADS = load_payloads()



def load_urls(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def get_response(url):
    try:
        r = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        return {
            "status": r.status_code,
            "len": len(r.text),
            "body": r.text[:4000]
        }

    except Exception as e:
        return {
            "status": "ERR",
            "len": 0,
            "body": str(e)
        }


def fetch_url(url):
    try:
        r = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        return r.text[:5000]

    except Exception as e:
        return f"Error fetching URL: {e}"


# =========================
# PARAMETER FUZZER (ELITE)
# =========================
def fuzz_url(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        print("No parameters found in URL.")
        return

    baseline = get_response(url)

    print(f"\nBaseline -> Status: {baseline['status']} | Length: {baseline['len']}")
    print("=" * 70)

    findings = []

    for param in params:
        for payload in FUZZ_PAYLOADS:

            test_url = replace_param(url, param, payload)
            result = get_response(test_url)

            score = 0
            reasons = []
            body = result["body"].lower()

            # Status change
            if result["status"] != baseline["status"]:
                score += 20
                reasons.append("Status changed")

            # Length delta
            delta = abs(result["len"] - baseline["len"])
            if delta > 100:
                score += 15
                reasons.append(f"Length delta ({delta})")

            # SQL error detection
            sql_words = [
                "sql", "mysql", "sqlite", "postgres",
                "syntax error", "warning", "odbc", "pdo"
            ]

            if any(w in body for w in sql_words):
                score += 40
                reasons.append("SQL error keyword")

            # Reflection
            if payload.lower() in body:
                score += 25
                reasons.append("Payload reflected")

            # LFI / file disclosure
            if "root:x:" in body or "[extensions]" in body:
                score += 50
                reasons.append("Possible file disclosure")

            # XSS reflection
            if "<script" in body:
                score += 45
                reasons.append("Possible XSS reflection")

            # Server error
            if result["status"] == 500:
                score += 20
                reasons.append("500 server error")

            # Severity
            if score >= 90:
                severity = "CRITICAL"
            elif score >= 70:
                severity = "HIGH"
            elif score >= 45:
                severity = "MEDIUM"
            elif score >= 20:
                severity = "LOW"
            else:
                severity = None

            if severity:
                PAYLOAD_INDEX[payload].append({
                    "url": test_url,
                    "param": param,
                    "severity": severity,
                    "score": score
                })
                finding = {
                    "source": "fuzzer",
                    "url": test_url,
                    "param": param,
                    "type": "sqli/xss/lfi/unknown",
                    "raw_signal": {
                        "payload": payload,
                        "status": result["status"],
                        "length": result["len"],
                        "reasons": reasons
                    },
                    "confidence": score,
                    "severity": severity
                }

                findings.append(finding)

                print("\n[FINDING]")
                print(finding)

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    if not findings:
        print("No strong findings detected.")
        return

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for f in findings:
        counts[f["severity"]] += 1

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"{sev}: {counts[sev]}")

    print("\nTop Findings:")

    findings.sort(key=lambda x: x["confidence"], reverse=True)

    for f in findings[:10]:
        print(
            f"[{f['severity']}] "
            f"{f['param']} | {f['raw_signal']['payload']} | Score {f['confidence']}"
        )
    with open("payload_url_map.json", "w", encoding="utf-8") as f:
        json.dump(PAYLOAD_INDEX, f, indent=2)       
    print("\nSaved: payload_url_map.json")    

# =========================
# RAG HELPERS
# =========================
def chunk_text(text, size):
    return [text[i:i + size] for i in range(0, len(text), size)]


def score_chunk(chunk, query):
    chunk_lower = chunk.lower()

    words = re.findall(r"\w+", query.lower())
    words = [w for w in words if len(w) > 3]

    score = 0

    for word in words:
        if word in chunk_lower:
            score += 2

    return score


def build_context(query):
    results = []

    for file in os.listdir(BASE_DIR):
        if file.endswith(".txt"):
            path = os.path.join(BASE_DIR, file)

            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()

            chunks = chunk_text(text, CHUNK_SIZE)

            for chunk in chunks:
                score = score_chunk(chunk, query)

                if score >= 2:
                    results.append((score, f"[{file}]\n{chunk}"))

    results.sort(reverse=True, key=lambda x: x[0])

    top_chunks = [chunk for _, chunk in results[:MAX_RESULTS]]

    print(f"\n[INFO] Using top {len(top_chunks)} context chunks...")

    if not top_chunks:
        return ""

    return "\n\n---\n\n".join(top_chunks)


# =========================
# OLLAMA ASK
# =========================
def ask_ai(query):
    context = build_context(query)

    if not context:
        print("No relevant info found.")
        return

    prompt = f"""
You are a professional web security tester.

STRICT RULES:
- Respond ONLY in English
- Be concise and technical
- Do NOT ask questions

TASK:
Analyze the provided data and identify potential vulnerabilities.

LOOK FOR:
- SQL Injection
- XSS
- IDOR
- Authentication issues
- Misconfigurations
- Information leakage

CONTEXT:
{context}

INPUT:
{query}

OUTPUT FORMAT:
- Findings:
- Evidence:
- Why it matters:
- Suggested next steps:
""".strip()

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        },
        timeout=120
    )


    print("\n" + "=" * 60)
    print("RESULT")
    print("=" * 60)

    #clean = raw.strip()
    #print(clean)
    print("=" * 60)

def crawl_target(target):
    print("\nRunning GoSpider...")
    subprocess.run(
        f'gospider -s {target} -d 2 -c 10 -q > gospider.txt',
        shell=True
    )

    print("Running Katana...")
    subprocess.run(
        f'katana -u {target} -d 2 -silent > katana.txt',
        shell=True
    )

    urls = set()

    for file in ["gospider.txt", "katana.txt"]:
        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("http"):
                        urls.add(line)
        except:
            pass

    with open("urls.txt", "w") as f:
        for u in sorted(urls):
            f.write(u + "\n")

    param_urls = []
    plain_urls = []

    for u in urls:
        if "?" in u and "=" in u:
            param_urls.append(u)
        else:
            plain_urls.append(u)

    with open("param_urls.txt", "w") as f:
        f.write("\n".join(param_urls))

    with open("plain_urls.txt", "w") as f:
        f.write("\n".join(plain_urls))

    print(f"\nTotal URLs: {len(urls)}")
    print(f"Param URLs: {len(param_urls)}")
    print(f"Plain URLs: {len(plain_urls)}")


def dedupe_param_urls(urls):
    seen = set()
    unique = []

    for url in urls:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            key = (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                tuple(sorted(params.keys()))
            )

            if key not in seen:
                seen.add(key)
                unique.append(url)

        except:
            pass

    return unique

def scan_list(file_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            urls = [line.strip() for line in f if line.strip()]

        print(f"\nLoaded {len(urls)} URLs\n")

        for i, url in enumerate(urls, 1):
            print("=" * 60)
            print(f"[{i}/{len(urls)}] Scanning: {url}")
            print("=" * 60)

            response = fetch_url(url)
            query = f"Analyze this HTTP response for vulnerabilities:\n\n{response}"
            ask_ai(query)

    except Exception as e:
        print("Error:", e)


# =========================
# MAIN MENU
# =========================
mode = input("Mode (ask / scan / scanlist / fuzz / fuzzlist / hunt / crawl): ").strip().lower()
if mode == "ask":
    QUERY = input("Ask something: ").strip()
    ask_ai(QUERY)

elif mode == "scan":
    TARGET = input("Enter URL: ").strip()
    RESPONSE = fetch_url(TARGET)

    QUERY = f"Analyze this HTTP response for vulnerabilities:\n\n{RESPONSE}"
    ask_ai(QUERY)

elif mode == "scanlist":
    path = input("Enter file path: ").strip()
    scan_list(path)

elif mode == "fuzz":
    TARGET = input("Enter URL with parameters: ").strip()
    fuzz_url(TARGET)

elif mode == "bulk-fuzz":
    file_path = input("Enter path to URL list: ").strip()

    urls = load_urls(file_path)

    print(f"\nLoaded {len(urls)} URLs")

    for url in urls:
        print("\n" + "=" * 80)
        print("Fuzzing:", url)
        fuzz_url(url)

elif mode == "crawl":
    TARGET = input("Enter domain: ").strip()
    crawl_target(TARGET)


elif mode == "fuzzlist":
    path = input("Enter file path: ").strip()

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            urls = [line.strip() for line in f if line.strip()]

        original = len(urls)
        urls = dedupe_param_urls(urls)

        print(f"\nLoaded {original} URLs")
        print(f"Deduplicated to {len(urls)} unique parameter patterns\n")

        for i, url in enumerate(urls, 1):
            print("=" * 70)
            print(f"[{i}/{len(urls)}] Testing: {url}")
            print("=" * 70)
            fuzz_url(url)

    except Exception as e:
        print("Error:", e)
else:
    print("Invalid mode.")