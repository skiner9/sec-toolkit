# sec-toolkit

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
| 2 | `passaudit` | Password strength checker, hash cracker, breach checker | 🔧 Coming |
| 3 | `urldetect` | ML-based phishing URL classifier | 🔧 Coming |
| 4 | `sniffer` | Packet capture and protocol analysis | 🔧 Coming |
| 5 | `osint` | Automated OSINT recon with HTML report | 🔧 Coming |
| 6 | `logaudit` | Auth and web log anomaly detector | 🔧 Coming |

---

## Setup

**Requirements:** Python 3.10+, Linux or WSL2

```bash
git clone https://github.com/skiner9/sec-toolkit.git
cd sec-toolkit
pip install -r requirements.txt
```

---

## Tool 1 — Port Scanner

A fast multithreaded TCP port scanner with service detection, banner grabbing,
and OS fingerprinting. Outputs results to the terminal and generates JSON or HTML reports.

### How it works

1. Takes a target IP or hostname and a port range as input
2. Spins up to 500 concurrent threads — each thread checks one port simultaneously
3. For every open port found, connects again to grab the service banner
4. Sends an ICMP ping and reads the TTL value to guess the operating system
5. Saves a report as JSON (for parsing) or HTML (for viewing in browser)

### Usage

```bash
# Scan common ports
python3 tools/scanner/scanner.py --target 192.168.1.1

# Scan a full port range
python3 tools/scanner/scanner.py --target 192.168.1.1 --ports 1-1024 --threads 200

# Scan specific ports only
python3 tools/scanner/scanner.py --target 192.168.1.1 --ports 22,80,443

# Save an HTML report
python3 tools/scanner/scanner.py --target 192.168.1.1 --report html

# Save both JSON and HTML
python3 tools/scanner/scanner.py --target 192.168.1.1 --report both --output reports/
```

### Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--target` | required | IP address or hostname to scan |
| `--ports` | `common` | `common`, `1-1024`, or `22,80,443` |
| `--threads` | `100` | Concurrent threads — higher is faster |
| `--timeout` | `1.0` | Seconds to wait per port before giving up |
| `--report` | `json` | Output format: `json`, `html`, or `both` |
| `--output` | `reports/` | Folder to save report files |

### Example output
==================================================
Port Scanner v1.0
sec-toolkit | for authorised use only
[] Resolved scanme.nmap.org → 45.33.32.156
[] Target  : scanme.nmap.org (45.33.32.156)
[] Ports   : 20 to scan
[] Threads : 100 | Timeout: 1.0s
[+]    22/TCP  ssh          — SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
[+]    80/TCP  http         — HTTP/1.1 200 OK
──────────────────── Scan Complete ────────────────────
[+] Found 2 open port(s) in 1.78s
[*] OS guess: Linux / Unix (TTL=54)
[+] JSON report → reports/45_33_32_156_20260608.json

---

## Project structure
sec-toolkit/
├── utils/
│   ├── output.py        # Rich terminal output (colours, progress bar)
│   └── reporter.py      # JSON and HTML report generation
├── tools/
│   ├── scanner/         # Phase 1 — port scanner
│   ├── passaudit/       # Phase 2 — password auditor (coming)
│   ├── urldetect/       # Phase 3 — phishing detector (coming)
│   ├── sniffer/         # Phase 4 — packet sniffer (coming)
│   ├── osint/           # Phase 5 — OSINT recon (coming)
│   └── logaudit/        # Phase 6 — log analyzer (coming)
├── reports/             # Generated scan output files
├── requirements.txt
└── README.md

---

## Skills demonstrated

- Raw socket programming in Python (`socket`, `struct`)
- Multithreading with `ThreadPoolExecutor` for high-speed scanning
- TCP/IP networking — how ports and connections work
- Service banner grabbing and fingerprinting
- TTL-based OS detection using ICMP
- CLI tool design with `argparse`
- Terminal UI with the `rich` library
- Automated HTML report generation

---

## Dependencies
rich>=13.0.0

All other modules (`socket`, `threading`, `struct`, `argparse`, `json`) are Python standard library — no extra installation needed.

---

## Legal

This tool is intended for **authorised security testing and educational use only**.
The author is not responsible for any misuse. Always get written permission before
scanning any network or system you do not own.