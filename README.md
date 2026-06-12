You're right — your README has a major formatting problem. The code blocks lost their   markers, so all your commands are running together as one paragraph instead of showing as separate code lines. That's why "Usage" looks like a wall of text.
Here is a complete clean README. Open README.md in VS Code, delete absolutely everything, then copy-paste this entire block exactly:
markdown# sec-toolkit

A modular Python security toolkit built as a hands-on cybersecurity portfolio project.
Each tool covers a different area of offensive and defensive security.

> ⚠️ **Legal notice:** All tools in this repository are for **educational purposes only**.
> Only use them on systems you own or have **explicit written permission** to test.
> Unauthorised scanning or probing is illegal in most countries.

---

## Tools

| # | Tool | Description | Status |
|---|------|-------------|--------|
| 1 | `scanner` | TCP port scanner with banner grabbing and OS detection | ✅ Complete |
| 2 | `passaudit` | Password strength checker, hash cracker, breach checker | ✅ Complete |
| 3 | `urldetect` | ML-based phishing URL classifier (90% accuracy) | ✅ Complete |
| 4 | `sniffer` | Packet capture and protocol analysis | 🔧 Coming |
| 5 | `osint` | Automated OSINT recon with HTML report | 🔧 Coming |
| 6 | `logaudit` | Auth and web log anomaly detector | 🔧 Coming |

---

## Setup

**Requirements:** Python 3.10+

Clone the repository and install dependencies:

~~~bash
git clone https://github.com/skiner9/sec-toolkit.git
cd sec-toolkit
pip3 install -r requirements.txt --break-system-packages
~~~

### Wordlist Setup (required for hash cracking)

The password cracker uses the **crackstation-human wordlist** (~65 million passwords, ~246MB).
It is too large to include in the repo. Run the setup script to download and extract it:

~~~bash
bash setup.sh
~~~

This will create `tools/passaudit/wordlists/` and download `crackstation-human-only.txt.gz` (~246MB).

> ⚠️ You must run `bash setup.sh` before using `--mode crack`.

### ML Model Setup (required for phishing detection)

The phishing detector includes a pre-trained model in the repo. If you want to retrain it from scratch on the included dataset:

~~~bash
python3 tools/urldetect/train.py
~~~

---

## Tool 1 — Port Scanner

A fast multithreaded TCP port scanner with service detection, banner grabbing, and OS fingerprinting.

### How it works

1. Takes a target IP or hostname and an optional port range as input
2. Spins up to 100 concurrent threads — each thread checks one port simultaneously
3. For every open port found, connects again to grab the service banner
4. Sends an ICMP ping and reads the TTL value to guess the operating system
5. Optionally saves a report as JSON or HTML

### Usage

**Scan default common ports (20 ports total):**
~~~bash
python3 tools/scanner/scanner.py --target 192.168.1.1
~~~

**Scan a specific port range:**
~~~bash
python3 tools/scanner/scanner.py --target 192.168.1.1 --ports 1-1024
~~~

**Scan all 65,535 ports:**
~~~bash
python3 tools/scanner/scanner.py --target 192.168.1.1 --ports 1-65535
~~~

**Scan specific ports only:**
~~~bash
python3 tools/scanner/scanner.py --target 192.168.1.1 --ports 22,80,443
~~~

**Save a JSON report:**
~~~bash
python3 tools/scanner/scanner.py --target 192.168.1.1 --report json
~~~

**Save an HTML report:**
~~~bash
python3 tools/scanner/scanner.py --target 192.168.1.1 --report html
~~~

**Save both JSON and HTML:**
~~~bash
python3 tools/scanner/scanner.py --target 192.168.1.1 --report both --output reports/
~~~

### Default Port List

By default (without `--ports`), the scanner checks these **20 common ports**:

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21 | FTP | 443 | HTTPS |
| 22 | SSH | 445 | SMB |
| 23 | Telnet | 993 | IMAPS |
| 25 | SMTP | 995 | POP3S |
| 53 | DNS | 3306 | MySQL |
| 80 | HTTP | 3389 | RDP |
| 110 | POP3 | 5900 | VNC |
| 111 | RPC | 8080 | HTTP-Alt |
| 135 | RPC | 8443 | HTTPS-Alt |
| 139 | NetBIOS | 143 | IMAP |

### Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--target` | required | IP address or hostname to scan |
| `--ports` | `common` | `common`, `1-1024`, `1-65535`, or `22,80,443` |
| `--threads` | `100` | Concurrent threads (higher = faster) |
| `--timeout` | `1.0` | Seconds to wait per port |
| `--report` | none | `json`, `html`, or `both` |
| `--output` | `reports/` | Folder to save report files |

### Example Output

~~~
==================================================
  Port Scanner v1.0
  sec-toolkit | for authorised use only
==================================================

[*] Target  : 192.168.1.1 (192.168.1.1)
[*] Ports   : 20 to scan
[*] Threads : 100 | Timeout: 1.0s

[+]    22/TCP  ssh          — SSH-2.0-OpenSSH_9.2
[+]    80/TCP  http         — HTTP/1.1 200 OK
[+]   445/TCP  smb

────────────────── Scan Complete ──────────────────
[+] Found 3 open port(s) in 1.78s
[*] OS guess: Windows (TTL=128)
~~~

---

## Tool 2 — Password Auditor

A three-in-one password auditing tool. Checks how strong a password is, attempts to crack a hash using a wordlist, and checks if a password has appeared in any known data breach.

### How it works

The tool has three modes selected with `--mode`:

1. **`check`** — analyses password strength using `zxcvbn` (the same library Dropbox uses). Reports the score, estimated crack time, and suggestions.
2. **`crack`** — performs a dictionary attack on a hash using the **65-million password crackstation wordlist**. Supports MD5, SHA1, SHA256, and SHA512 (auto-detected by hash length).
3. **`breach`** — checks the Have I Been Pwned database. Uses **k-anonymity** so the actual password never leaves your machine — only the first 5 characters of its SHA1 hash are sent.

> ⚠️ Run `bash setup.sh` before using `--mode crack`.

### Usage

**Check password strength:**
~~~bash
python3 tools/passaudit/passaudit.py --mode check --password "MyPass123"
~~~

**Crack an MD5 hash (after running setup.sh):**
~~~bash
python3 tools/passaudit/passaudit.py --mode crack --hash 5f4dcc3b5aa765d61d8327deb882cf99
~~~

**Crack with a custom wordlist:**
~~~bash
python3 tools/passaudit/passaudit.py --mode crack --hash <hash> --wordlist /path/to/list.txt
~~~

**Check if a password has been breached:**
~~~bash
python3 tools/passaudit/passaudit.py --mode breach --password "password123"
~~~

### Arguments

| Argument | Required for | Description |
|----------|--------------|-------------|
| `--mode` | always | `check`, `crack`, or `breach` |
| `--password` | check, breach | The password to analyse |
| `--hash` | crack | The hash to crack (auto-detects type) |
| `--wordlist` | optional | Path to a custom wordlist file |

### Supported Hash Types

| Length | Algorithm |
|--------|-----------|
| 32 chars | MD5 |
| 40 chars | SHA1 |
| 64 chars | SHA256 |
| 128 chars | SHA512 |

### Example Output

~~~
══════════ Password Strength Analysis ══════════
  Password : MyPass123
  Length   : 9 characters
  Score    : 1/4 — Weak
  Cracks in: 2 hours

[!] Warning : This is similar to a commonly used password
[*] Suggestions:
   • Add another word or two
   • Avoid repeated characters
~~~

~~~
══════════ Breach Check (HaveIBeenPwned) ══════════
[*] Sending hash prefix 5BAA6 to api.pwnedpasswords.com
[*] Your actual password never leaves this computer (k-anonymity)

[-] PWNED! This password has been seen 10,434,004 times in breaches.
[!] Change it everywhere you used it.
~~~

---

## Tool 3 — Phishing URL Detector

An ML-powered phishing URL classifier that uses a Random Forest model trained on 58,000+ labeled URLs. Combines machine learning prediction with a known-safe-domain allow-list and heuristic rules to minimize false positives.

### How it works

1. Takes any URL as input
2. Extracts ~19 measurable features (length, hyphens, special characters, domain age indicators, etc.)
3. Runs the features through a trained Random Forest classifier (90% accuracy)
4. Cross-checks against a built-in allow-list of trusted brands (google, github, microsoft, etc.)
5. Returns a verdict: **SAFE**, **SUSPICIOUS**, or **PHISHING**, along with the human-readable reasons

### Usage

**Check a known safe website:**
~~~bash
python3 tools/urldetect/urldetect.py --url https://www.google.com
~~~

**Check a suspicious lookalike domain:**
~~~bash
python3 tools/urldetect/urldetect.py --url http://paypa1-secure-login.com/verify-account
~~~

**Check an IP-based URL (common phishing trick):**
~~~bash
python3 tools/urldetect/urldetect.py --url http://192.168.1.5/login.php
~~~

**Check a long URL with suspicious keywords:**
~~~bash
python3 tools/urldetect/urldetect.py --url http://secure-banking-update.tk/account/verify?id=12345
~~~

**Retrain the model from the included dataset:**
~~~bash
python3 tools/urldetect/train.py
~~~

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--url` | yes | The URL to analyse |

### Features Extracted

| Feature | What it measures |
|---------|------------------|
| URL length | Phishing URLs tend to be longer |
| Number of dots | Multiple subdomains can be suspicious |
| Number of hyphens | `paypal-login.com` style attacks |
| Special characters | `@`, `%`, `&` in unusual places |
| Domain length | Very long domains are often phishing |
| IP instead of domain | Major red flag |
| URL shortener | Hides real destination |
| Suspicious keywords | `login`, `verify`, `secure`, `bank`, etc. |
| HTTPS presence | Encrypted vs unencrypted |
| Domain entropy | Random-looking strings score higher |

### Example Output

~~~
══════════ URL Analysis ══════════
  URL : http://paypa1-secure-login.com/verify-account

[-] VERDICT: PHISHING  (96.0% confidence)

[*] Reasons:
   • Contains hyphens in domain (paypal-login style)
   • No HTTPS — connection is not encrypted
   • Contains 4 suspicious keyword(s)
~~~

~~~
══════════ URL Analysis ══════════
  URL : https://www.google.com

[+] VERDICT: SAFE  (Known trusted domain)

[*] No red flags detected.
~~~

### Model Performance

| Metric | Score |
|--------|-------|
| Accuracy | 90.15% |
| Precision (phishing) | 91% |
| Recall (phishing) | 89% |
| F1-score | 0.90 |
| Training set | 46,916 URLs |
| Test set | 11,729 URLs |

Top 5 most important features identified by the model:
`directory_length`, `qty_slash_url`, `length_url`, `qty_dot_directory`, `domain_length`.

---

## Project Structure

~~~
sec-toolkit/
│
├── reports/                       # Generated scan output files
│
├── tools/
│   ├── scanner/                   # Tool 1 — port scanner
│   │   ├── __init__.py
│   │   └── scanner.py
│   │
│   ├── passaudit/                 # Tool 2 — password auditor
│   │   ├── __init__.py
│   │   ├── passaudit.py
│   │   └── wordlists/             # 65M password list (via setup.sh)
│   │
│   └── urldetect/                 # Tool 3 — phishing URL detector
│       ├── __init__.py
│       ├── urldetect.py
│       ├── train.py
│       ├── features.py
│       ├── data/
│       │   └── urls.csv           # Training dataset
│       └── models/
│           ├── phishing_model.joblib
│           └── feature_names.joblib
│
├── utils/
│   ├── __init__.py
│   ├── output.py                  # Rich terminal output
│   └── reporter.py                # JSON/HTML report generation
│
├── README.md
├── requirements.txt
└── setup.sh                       # Downloads the password wordlist
~~~

---

## Skills Demonstrated

**Tool 1 — Port Scanner**
- Raw socket programming (`socket`, `struct`)
- Multithreading with `ThreadPoolExecutor`
- TCP/IP networking
- Service banner grabbing and fingerprinting
- TTL-based OS detection using ICMP
- HTML report generation

**Tool 2 — Password Auditor**
- Cryptographic hashing (MD5, SHA1, SHA256, SHA512)
- Dictionary-based password attacks on a 65M wordlist
- Password strength analysis using entropy and pattern detection
- REST API integration with Have I Been Pwned
- k-anonymity model for privacy-preserving lookups

**Tool 3 — Phishing URL Detector**
- Machine learning with `scikit-learn` (Random Forest classifier)
- Feature engineering from URL strings
- Model training, evaluation, and persistence with `joblib`
- Handling imbalanced datasets and false positives
- Combining ML predictions with rule-based heuristics

**Across the toolkit**
- CLI tool design with `argparse`
- Terminal UI with `rich` (colours, tables, progress bars)
- Modular code architecture with shared utilities
- Git/GitHub version control

---

## Dependencies

~~~
rich>=13.0.0         # Terminal colours, tables, progress bars
zxcvbn>=4.5.0        # Password strength analysis
bcrypt>=4.0.0        # Bcrypt hash support
requests>=2.31.0     # HTTP client for HIBP API
scikit-learn>=1.3.0  # Machine learning (Random Forest)
pandas>=2.0.0        # Dataset handling
numpy>=1.24.0        # Numerical operations
tldextract>=5.0.0    # Domain parsing
joblib>=1.3.0        # Model persistence
~~~

All other modules (`socket`, `threading`, `struct`, `argparse`, `json`, `hashlib`, `re`) are Python standard library.

---

## Legal

This tool is intended for **authorised security testing and educational use only**.
The author is not responsible for any misuse.
Always get written permission before scanning any network or system you do not own.