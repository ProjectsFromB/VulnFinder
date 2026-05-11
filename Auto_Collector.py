import os
import re
import time
import json
import hashlib
import requests
import feedparser
import trafilatura
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# =====================================================
# BUG BOUNTY AUTO COLLECTOR
# Builds private RAG dataset from public sources
# =====================================================

# -------------------------
# CONFIG
# -------------------------
SAVE_DIR = "collector_data"
RAW_DIR = os.path.join(SAVE_DIR, "raw")
CLEAN_DIR = os.path.join(SAVE_DIR, "clean")
CHUNK_DIR = os.path.join(SAVE_DIR, "chunks")

MAX_PER_SOURCE = 1000
REQUEST_TIMEOUT = 20
SLEEP_BETWEEN = 1.0

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; ResearchCollector/1.0)"
}

# -------------------------
# PUBLIC SOURCES
# -------------------------
RSS_FEEDS = [
    "https://portswigger.net/daily-swig/rss",
    "https://portswigger.net/research/rss",
]

WEB_PAGES = [
    "https://portswigger.net/research",
    "https://www.intigriti.com/researchers/blog",
    "https://www.bugcrowd.com/blog/",
]

# -------------------------
# PREP DIRS
# -------------------------
for d in [SAVE_DIR, RAW_DIR, CLEAN_DIR, CHUNK_DIR]:
    os.makedirs(d, exist_ok=True)

# -------------------------
# HELPERS
# -------------------------
def sha_name(text):
    return hashlib.md5(text.encode()).hexdigest()

def safe_get(url):
    try:
        r = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers=HEADERS
        )
        return r.text
    except:
        return None

def save_text(folder, name, text):
    path = os.path.join(folder, name + ".txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)

def clean_text(text):
    lines = []

    for line in text.splitlines():
        line = line.strip()

        if len(line) < 30:
            continue

        if "cookie" in line.lower():
            continue

        lines.append(line)

    return "\n".join(lines)

def chunk_text(text, size=1200, overlap=150):
    chunks = []
    i = 0

    while i < len(text):
        chunk = text[i:i+size]
        chunks.append(chunk)
        i += size - overlap

    return chunks

# -------------------------
# EXTRACT LINKS FROM PAGE
# -------------------------
def extract_links(page_url):
    html = safe_get(page_url)

    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")
    found = set()

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()

        if href.startswith("#"):
            continue

        full = urljoin(page_url, href)

        parsed = urlparse(full)

        if parsed.scheme not in ["http", "https"]:
            continue

        found.add(full)

    return list(found)

# -------------------------
# PROCESS ARTICLE URL
# -------------------------
def process_url(url):
    html = safe_get(url)

    if not html:
        return False

    extracted = trafilatura.extract(html)

    if not extracted:
        return False

    raw_name = sha_name(url)

    raw_text = f"SOURCE: {url}\n\n{extracted}"
    save_text(RAW_DIR, raw_name, raw_text)

    cleaned = clean_text(raw_text)

    if len(cleaned) < 500:
        return False

    save_text(CLEAN_DIR, raw_name, cleaned)

    chunks = chunk_text(cleaned)

    for i, c in enumerate(chunks):
        obj = {
            "source": url,
            "chunk_id": i,
            "text": c,
            "tags": auto_tags(c)
        }

        with open(
            os.path.join(CHUNK_DIR, f"{raw_name}_{i}.json"),
            "w",
            encoding="utf-8"
        ) as f:
            json.dump(obj, f, indent=2)

    return True

# -------------------------
# AUTO TAGGING
# -------------------------
def auto_tags(text):
    t = text.lower()
    tags = []

    mapping = {
        "SQLi": ["sql injection", "mysql", "postgres", "union select"],
        "XSS": ["xss", "cross site scripting", "<script"],
        "SSRF": ["ssrf", "server side request forgery"],
        "IDOR": ["idor", "insecure direct object"],
        "LFI": ["path traversal", "/etc/passwd", "local file inclusion"],
        "RCE": ["remote code execution", "rce"],
        "Auth": ["oauth", "jwt", "authentication", "account takeover"],
        "GraphQL": ["graphql"],
        "Cloud": ["aws", "s3 bucket", "azure", "gcp"],
    }

    for tag, words in mapping.items():
        for w in words:
            if w in t:
                tags.append(tag)
                break

    return tags

# -------------------------
# RSS COLLECTION
# -------------------------
def collect_rss():
    total = 0

    for feed in RSS_FEEDS:
        print(f"[RSS] {feed}")

        try:
            parsed = feedparser.parse(feed)

            for entry in parsed.entries[:MAX_PER_SOURCE]:
                url = entry.link

                if process_url(url):
                    total += 1
                    print("[+] Saved:", url)

                time.sleep(SLEEP_BETWEEN)

        except Exception as e:
            print("RSS Error:", e)

    return total

# -------------------------
# WEB PAGE COLLECTION
# -------------------------
def collect_pages():
    total = 0

    for page in WEB_PAGES:
        print(f"[PAGE] {page}")

        urls = extract_links(page)

        count = 0

        for url in urls:
            if count >= MAX_PER_SOURCE:
                break

            if process_url(url):
                total += 1
                count += 1
                print("[+] Saved:", url)

            time.sleep(SLEEP_BETWEEN)

    return total

# -------------------------
# MAIN
# -------------------------
def main():
    print("=" * 60)
    print("BUG BOUNTY AUTO COLLECTOR")
    print("=" * 60)

    rss_count = collect_rss()
    page_count = collect_pages()

    print("\nDone.")
    print("RSS Articles :", rss_count)
    print("Page Articles:", page_count)
    print("Raw Folder   :", RAW_DIR)
    print("Clean Folder :", CLEAN_DIR)
    print("Chunk Folder :", CHUNK_DIR)

if __name__ == "__main__":
    main()