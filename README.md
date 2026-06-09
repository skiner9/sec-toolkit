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

**Requirements:** Python 3.10+

```bash
git clone https://github.com/skiner9/sec-toolkit.git
cd sec-toolkit
pip install -r requirements.txt
```

---

## Tool 1 — Port Scanner

A fast multithreaded TCP port scanner with service detection, banner grabbing, and OS fingerprinting.

### How it works

1. Takes a target IP or hostname and an optional port range as input
2. Spins up to 100 concurrent threads — each thread checks one port simultaneously
3. For every open port found, connects again to grab the service banner
4. Sends an ICMP ping and reads the TTL value to guess the operating system
5. Optionally saves a report as JSON or HTML — **only if you use the `--report` flag**

### Usage

```bash
# Scan default common ports (20 ports total)
python tools/scanner/scanner.py --target 192.168.1.1

# Scan a specific port range
python tools/scanner/scanner.py --target 192.168.1.1 --ports 1-1024

# Scan all ports
python tools/scanner/scanner.py --target 192.168.1.1 --ports 1-65535

# Scan specific ports only
python tools/scanner/scanner.py --target 192.168.1.1 --ports 22,80,443

# Save a JSON report (must be explicitly requested)
python tools/scanner/scanner.py --target 192.168.1.1 --report json

# Save an HTML report
python tools/scanner/scanner.py --target 192.168.1.1 --report html

# Save both JSON and HTML
python tools/scanner/scanner.py --target 192.168.1.1 --report both --output reports/
```

### Default Port Scan

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
| `--threads` | `100` | Concurrent threads — higher is faster |
| `--timeout` | `1.0` | Seconds to wait per port before giving up |
| `--report` | none | `json`, `html`, or `both` — not generated unless specified |
| `--output` | `reports/` | Folder to save report files |

### Example Output
==================================================
Port Scanner v1.0
sec-toolkit | for authorised use only
[] Target  : 192.168.1.1 (192.168.1.1)
[] Ports   : 20 to scan
[*] Threads : 100 | Timeout: 1.0s
[+]    22/TCP  ssh          SSH-2.0-OpenSSH_9.2
[+]    80/TCP  http         HTTP/1.1 200 OK
[+]   445/TCP  smb
────────────────── Scan Complete ──────────────────
[+] Found 3 open port(s) in 1.78s
[*] OS guess: Windows (TTL=128)

---

## Project Structure
sec-toolkit/
│
├── reports/              # Generated scan output files (JSON/HTML)
│
├── tools/
│   └── scanner/
│       ├── init.py
│       └── scanner.py    # Main scanner
│
├── utils/
│   ├── init.py
│   ├── output.py         # Terminal colours and display (rich)
│   └── reporter.py       # Saves results to JSON/HTML
│
├── README.md
└── requirements.txt

---

## Skills Demonstrated

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
pyfiglet

All other modules (`socket`, `threading`, `struct`, `argparse`, `json`) are Python standard library — no extra installation needed.

---

## Legal

This tool is intended for authorised security testing and educational use only.
The author is not responsible for any misuse.
Always get written permission before scanning any network or system you do not own.