# Bug Bounty AI Recon & Fuzzing Framework

An AI-assisted bug bounty reconnaissance, crawling, fuzzing, and vulnerability analysis framework built in Python.

This project combines:

* Automated crawling
* URL harvesting
* Parameter fuzzing
* Payload intelligence extraction
* AI-assisted vulnerability analysis
* Private RAG (Retrieval-Augmented Generation) knowledge building

Designed for:

* Bug bounty hunters
* Security researchers
* Web app penetration testers
* AI-assisted offensive security workflows

---

# Features

## 1. Automated Recon & Crawling

Uses:

* GoSpider
* Katana

To:

* Crawl targets
* Collect URLs
* Separate parameterized URLs
* Build fuzzing targets automatically

Outputs:

* `urls.txt`
* `param_urls.txt`
* `plain_urls.txt`

---

## 2. AI-Assisted Vulnerability Analysis

Uses:

* Ollama
* Qwen2.5

To analyze:

* HTTP responses
* Crawled data
* Recon findings

Detects:

* SQL Injection
* XSS
* IDOR
* Authentication issues
* Information disclosure
* Misconfigurations
* SSRF indicators
* LFI/RFI indicators

---

## 3. Smart Parameter Fuzzer

Automatically:

* Replaces URL parameters
* Injects payloads
* Detects anomalies
* Scores findings

Detection signals:

* Status code changes
* Response length deltas
* SQL errors
* Reflected payloads
* XSS indicators
* File disclosure patterns
* HTTP 500 errors

Severity levels:

* LOW
* MEDIUM
* HIGH
* CRITICAL

---

## 4. Auto Payload Intelligence Builder

Builds a reusable payload database from:

* Bug bounty reports
* Research articles
* Collected RAG data

Extracts:

* SQLi payloads
* XSS payloads
* LFI payloads
* SSRF payloads
* Redirect payloads
* Common vulnerable parameters

Outputs:

* `collector_data/intel/payload_bank.json`

---

## 5. Private Security RAG Dataset

Automatically scrapes and processes:

* PortSwigger research
* Intigriti blog
* Bugcrowd blog
* RSS feeds

Builds:

* Raw documents
* Cleaned documents
* Chunked RAG knowledge base

Used later for:

* AI-assisted vulnerability reasoning
* Payload generation
* Technique discovery
* Bug classification

---

# Project Structure

```text
project/
│
├── Ask.py
├── Auto_Collector.py
├── Payload_Intel_Builder.py
│
├── collector_data/
│   ├── raw/
│   ├── clean/
│   ├── chunks/
│   └── intel/
│       └── payload_bank.json
│
├── urls.txt
├── param_urls.txt
├── plain_urls.txt
├── payload_url_map.json
│
└── README.md
```

---

# Requirements

## Python

* Python 3.10+

## Python Packages

Install:

```bash
pip install requests beautifulsoup4 trafilatura feedparser
```

---

# External Tools

## GoSpider

GitHub:

[GoSpider](https://github.com/jaeles-project/gospider?utm_source=chatgpt.com)

Install:

```bash
go install github.com/jaeles-project/gospider@latest
```

---

## Katana

GitHub:

[Katana](https://github.com/projectdiscovery/katana?utm_source=chatgpt.com)

Install:

```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

---

## Ollama

Official Website:

[Ollama](https://ollama.com?utm_source=chatgpt.com)

Install a model:

```bash
ollama pull qwen2.5:7b
```

Start Ollama:

```bash
ollama serve
```

---

# Configuration

Inside `Ask.py`:

```python
BASE_DIR = "C:/Users/GUEST1/.openclaw/workspace/docs"
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5:7b"
```

Modify:

* model name
* RAG directory
* Ollama endpoint

As needed.

---

# Usage

# 1. Build RAG Dataset

Run:

```bash
python Auto_Collector.py
```

This:

* Collects research articles
* Cleans text
* Builds chunks
* Stores intelligence locally

---

# 2. Build Payload Intelligence

Run:

```bash
python Payload_Intel_Builder.py
```

This extracts:

* payloads
* parameters
* fuzz words

From your collected intelligence.

Output:

```text
collector_data/intel/payload_bank.json
```

---

# 3. Run Main Framework

Run:

```bash
python Ask.py
```

Modes:

```text
ask
scan
scanlist
fuzz
fuzzlist
crawl
```

---

# Mode Examples

## Ask AI Questions

```text
Mode: ask
```

Example:

```text
Analyze common SSRF patterns in cloud apps
```

---

## Scan Single URL

```text
Mode: scan
```

Example:

```text
https://target.com
```

Fetches:

* HTTP response
* AI vulnerability analysis

---

## Scan URL List

```text
Mode: scanlist
```

Input:

* File containing URLs

---

## Crawl Target

```text
Mode: crawl
```

Example:

```text
https://target.com
```

Runs:

* GoSpider
* Katana

Outputs discovered URLs.

---

## Fuzz Single URL

```text
Mode: fuzz
```

Example:

```text
https://target.com/page?id=1
```

Performs:

* Parameter fuzzing
* Reflection checks
* Error analysis
* Severity scoring

---

## Bulk Fuzz URLs

```text
Mode: fuzzlist
```

Input:

* File containing parameterized URLs

Automatically:

* Deduplicates parameter patterns
* Fuzzes all discovered parameters

---

# Finding Scoring Logic

Signals used:

| Signal                | Score |
| --------------------- | ----- |
| Status change         | +20   |
| Response length delta | +15   |
| SQL error keyword     | +40   |
| Reflected payload     | +25   |
| File disclosure       | +50   |
| XSS reflection        | +45   |
| HTTP 500 error        | +20   |

Severity mapping:

| Score | Severity |
| ----- | -------- |
| 90+   | CRITICAL |
| 70+   | HIGH     |
| 45+   | MEDIUM   |
| 20+   | LOW      |

---

# Example Workflow

## Step 1

Collect research:

```bash
python Auto_Collector.py
```

---

## Step 2

Build payload intelligence:

```bash
python Payload_Intel_Builder.py
```

---

## Step 3

Crawl target:

```bash
python Ask.py
```

Choose:

```text
crawl
```

---

## Step 4

Fuzz discovered URLs:

```text
fuzzlist
```

Use:

```text
param_urls.txt
```

---

## Step 5

Analyze responses with AI

Use:

* `scan`
* `scanlist`
* `ask`

---

# Output Files

| File                   | Purpose                     |
| ---------------------- | --------------------------- |
| `urls.txt`             | All discovered URLs         |
| `param_urls.txt`       | URLs with parameters        |
| `plain_urls.txt`       | Non-parameterized URLs      |
| `payload_url_map.json` | Payload-to-URL mapping      |
| `payload_bank.json`    | Extracted reusable payloads |

---

# Future Improvements

Planned ideas:

* Async HTTP fuzzing
* Multi-threaded scanning
* Headless browser integration
* JavaScript endpoint extraction
* GraphQL testing
* Automatic SSRF validation
* AI-generated payload mutations
* Burp Suite integration
* SQLite/PostgreSQL storage
* Vector embeddings
* Local semantic search
* Autonomous recon pipelines

---

# Legal Disclaimer

This project is for:

* Authorized security testing
* Educational purposes
* Bug bounty programs with permission

Do NOT use this framework against systems you do not own or have explicit authorization to test.

The author is not responsible for misuse or illegal activity.

---

# Credits

Research Sources:

* [PortSwigger Research](https://portswigger.net/research?utm_source=chatgpt.com)
* [Intigriti Blog](https://www.intigriti.com/researchers/blog?utm_source=chatgpt.com)
* [Bugcrowd Blog](https://www.bugcrowd.com/blog/?utm_source=chatgpt.com)

Tools Used:

* [Ollama](https://ollama.com?utm_source=chatgpt.com)
* [GoSpider](https://github.com/jaeles-project/gospider?utm_source=chatgpt.com)
* [Katana](https://github.com/projectdiscovery/katana?utm_source=chatgpt.com)

Models:

* Qwen
