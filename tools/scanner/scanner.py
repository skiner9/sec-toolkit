"""
Port Scanner — sec-toolkit
What it does: knocks on each port of a target computer to see which
ones are open, grabs the service banner, and saves a report.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import socket        # lets Python open network connections
import struct        # lets Python read raw binary data (used for ICMP/OS detection)
import argparse      # handles command-line arguments like --target and --ports
import threading     # lets us run many port checks at the same time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed  # manages our thread pool

from utils import output as out
from utils.reporter import save_json, save_html


# ── Known port numbers and their service names ─────────────────────────────
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 3306, 3389, 5900, 8080, 8443,
]

SERVICE_MAP = {
    21: "ftp",    22: "ssh",      23: "telnet",  25: "smtp",
    53: "dns",    80: "http",     110: "pop3",   143: "imap",
    443: "https", 445: "smb",     3306: "mysql", 3389: "rdp",
    5900: "vnc",  8080: "http-alt", 8443: "https-alt",
}


# ── OS guess from TTL value ────────────────────────────────────────────────
# Every computer puts a TTL number in network packets.
# Windows uses ~128, Linux uses ~64, Cisco uses ~255.
# We send a ping and read the TTL to guess the OS.
TTL_OS_MAP = {
    range(0,   65):  "Linux / Unix",
    range(65,  129): "Windows",
    range(129, 256): "Cisco / Network device",
}


# ── Banner grabbing ────────────────────────────────────────────────────────
# After finding an open port, we connect again and listen for what
# the service says about itself (e.g. "SSH-2.0-OpenSSH_9.2").
def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        try:
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        except socket.timeout:
            # Web ports need us to ask first before they respond
            if port in (80, 8080, 443, 8443):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            else:
                banner = ""
        s.close()
        return banner.split("\n")[0][:120]  # return only the first line, max 120 chars
    except Exception:
        return ""


# ── OS detection ──────────────────────────────────────────────────────────
# Sends a ping (ICMP packet) and reads the TTL from the response.
# Needs root/sudo to send raw packets — falls back gracefully if not available.
def guess_os(ip: str) -> str:
    try:
        # Build an ICMP echo request packet manually using struct
        icmp_type, code, checksum, identifier, sequence = 8, 0, 0, 1, 1
        header = struct.pack("bbHHh", icmp_type, code, checksum, identifier, sequence)
        data   = b"abcdefghijklmnop"

        def calc_checksum(source):
            s = 0
            for i in range(0, len(source), 2):
                w = source[i] + (source[i+1] << 8 if i+1 < len(source) else 0)
                s = (s + w) & 0xFFFF
            return ~s & 0xFFFF

        checksum = calc_checksum(header + data)
        header   = struct.pack("bbHHh", icmp_type, code, checksum, identifier, sequence)

        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        raw.settimeout(2)
        raw.sendto(header + data, (ip, 0))
        recv_packet, _ = raw.recvfrom(1024)
        raw.close()

        ttl = recv_packet[8]  # TTL is always at byte 8 of the IP header
        for rng, name in TTL_OS_MAP.items():
            if ttl in rng:
                return f"{name} (TTL={ttl})"
        return f"Unknown (TTL={ttl})"
    except PermissionError:
        return "Unknown (run with sudo for OS detection)"
    except Exception:
        return "Unknown (no ICMP response)"


# ── TCP port check ─────────────────────────────────────────────────────────
# Tries to connect to one port. If connection succeeds → port is open.
# socket.connect_ex() returns 0 on success, any other number means closed/filtered.
def tcp_scan_port(ip: str, port: int, timeout: float) -> dict | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:  # 0 = connection succeeded = port is open
            return {
                "port":     port,
                "protocol": "tcp",
                "state":    "open",
                "service":  SERVICE_MAP.get(port, "unknown"),
                "banner":   grab_banner(ip, port, timeout),
            }
    except Exception:
        pass
    return None  # None means closed or no response


# ── Port range parser ──────────────────────────────────────────────────────
# Converts the --ports argument into a list of integers.
# "common"    → the 20 well-known ports list above
# "1-1024"    → every number from 1 to 1024
# "22,80,443" → just those three ports
def parse_ports(port_arg: str) -> list[int]:
    if port_arg == "common":
        return COMMON_PORTS
    ports = []
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


# ── Hostname resolver ──────────────────────────────────────────────────────
# Converts a hostname like "scanme.nmap.org" into an IP address like "45.33.32.156"
def resolve(target: str) -> str:
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            out.info(f"Resolved [bold]{target}[/bold] → {ip}")
        return ip
    except socket.gaierror:
        out.error(f"Cannot resolve host: {target}")
        sys.exit(1)


# ── Main scanner class ─────────────────────────────────────────────────────
class PortScanner:
    def __init__(self, target, ports, threads=100, timeout=1.0):
        self.target  = target
        self.ip      = resolve(target)   # convert hostname to IP
        self.ports   = ports
        self.threads = threads           # how many ports to check at the same time
        self.timeout = timeout           # how long to wait before giving up on a port
        self.results = []
        self._lock   = threading.Lock() # prevents two threads writing results at same time

    def run(self) -> list[dict]:
        from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn

        out.info(f"Target  : [bold]{self.target}[/bold] ({self.ip})")
        out.info(f"Ports   : {len(self.ports)} to scan")
        out.info(f"Threads : {self.threads} | Timeout: {self.timeout}s\n")

        # Progress bar shown in the terminal while scanning
        with Progress(SpinnerColumn(), "[progress.description]{task.description}",
                      BarColumn(), TaskProgressColumn(), TimeElapsedColumn()) as progress:
            task = progress.add_task("Scanning...", total=len(self.ports))

            # ThreadPoolExecutor runs self.threads port checks simultaneously
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(tcp_scan_port, self.ip, port, self.timeout): port
                           for port in self.ports}

                for future in as_completed(futures):
                    result = future.result()
                    if result:  # if port was open (not None)
                        with self._lock:
                            self.results.append(result)
                            banner = f" — {result['banner']}" if result["banner"] else ""
                            out.success(
                                f"[bold]{result['port']:>5}/TCP[/bold]  "
                                f"[cyan]{result['service']:<12}[/cyan]{banner}"
                            )
                    progress.advance(task)

        self.results.sort(key=lambda x: x["port"])  # sort results by port number
        return self.results


# ── Entry point — runs when you type: python scanner.py --target x.x.x.x ──
def main():
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="sec-toolkit port scanner",
        epilog="Only scan systems you own or have explicit written permission to test."
    )
    parser.add_argument("--target",  required=True,  help="IP address or hostname")
    parser.add_argument("--ports",   default="common", help="common | 1-1024 | 22,80,443")
    parser.add_argument("--threads", type=int,   default=100,  help="Concurrent threads (default 100)")
    parser.add_argument("--timeout", type=float, default=1.0,  help="Seconds to wait per port (default 1.0)")
    #parser.add_argument("--report",  choices=["json","html","both"], default="json")
    parser.add_argument("--report",  choices=["json","html","both"], default=None)
    parser.add_argument("--output",  default="reports", help="Folder to save reports")
    args = parser.parse_args()

    out.banner("Port Scanner")

    ports      = parse_ports(args.ports)
    scanner    = PortScanner(args.target, ports, args.threads, args.timeout)
    start_time = datetime.now()
    results    = scanner.run()
    duration   = round((datetime.now() - start_time).total_seconds(), 2)

    out.console.print()
    out.console.rule("[bold magenta]Scan Complete[/bold magenta]")
    out.success(f"Found [bold]{len(results)}[/bold] open port(s) in {duration}s")

    if not results:
        out.warning("No open ports found. Host may be offline or firewalled.")

    # OS detection
    out.info("Running OS detection...")
    os_guess = guess_os(scanner.ip)
    out.info(f"OS guess: [bold]{os_guess}[/bold]")

    # Save report
    report_data = {
        "target":           args.target,
        "ip":               scanner.ip,
        "scan_time":        start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds": duration,
        "total_scanned":    len(ports),
        "os_guess":         os_guess,
        "open_ports":       results,
    }

    timestamp = start_time.strftime("%Y%m%d_%H%M%S")
    base      = f"{scanner.ip.replace('.','_')}_{timestamp}"

    if args.report in ("json", "both"):
        path = save_json(report_data, f"{args.output}/{base}.json")
        out.success(f"JSON report → {path}")

    elif args.report in ("html", "both"):
        path = save_html(report_data, f"{args.output}/{base}.html")
        out.success(f"HTML report → {path}")


if __name__ == "__main__":
    main()