"""
Packet Sniffer — sec-toolkit

Captures and analyses network traffic in real-time.
Features:
  - Live capture of TCP, UDP, ICMP packets
  - Protocol filtering (HTTP, DNS, TCP, UDP, ICMP)
  - Credential detection on insecure protocols (HTTP basic auth, FTP, Telnet)
  - PCAP export for analysis in Wireshark

⚠️  Must be run with Administrator/root privileges (sniffers need raw socket access).
⚠️  Only sniff networks you own or have permission to monitor.
"""

import sys
import os
import argparse
import re
from datetime import datetime
from collections import Counter
from pathlib import Path

# Make utils importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, get_if_list
from scapy.layers.http import HTTPRequest, HTTP

from utils import output as out


# ── Stats counters ────────────────────────────────────────────────────────
stats = Counter()
captured_packets = []


# ── Credential detection patterns ─────────────────────────────────────────
# These regex patterns look for usernames/passwords in cleartext traffic.
CREDENTIAL_PATTERNS = [
    (re.compile(rb"USER\s+(\S+)", re.IGNORECASE),     "FTP Username"),
    (re.compile(rb"PASS\s+(\S+)", re.IGNORECASE),     "FTP Password"),
    (re.compile(rb"login:\s*(\S+)", re.IGNORECASE),   "Telnet Login"),
    (re.compile(rb"password:\s*(\S+)", re.IGNORECASE),"Telnet Password"),
    (re.compile(rb"username=([^&\s]+)", re.IGNORECASE),"HTTP form username"),
    (re.compile(rb"password=([^&\s]+)", re.IGNORECASE),"HTTP form password"),
    (re.compile(rb"Authorization:\s*Basic\s+(\S+)"),   "HTTP Basic Auth"),
]


def detect_credentials(payload: bytes):
    """Scan raw packet payload for cleartext credentials."""
    findings = []
    for pattern, label in CREDENTIAL_PATTERNS:
        match = pattern.search(payload)
        if match:
            value = match.group(1).decode("utf-8", errors="ignore")
            findings.append((label, value))
    return findings


def process_packet(pkt):
    """Called once per captured packet. Decodes it, prints info, updates stats."""
    captured_packets.append(pkt)

    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst

    # ── TCP ────────────────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        stats["TCP"] += 1

        # HTTP detection (port 80 or HTTP layer)
        if pkt.haslayer(HTTPRequest):
            http = pkt[HTTPRequest]
            method = http.Method.decode(errors="ignore") if http.Method else "?"
            host   = http.Host.decode(errors="ignore")   if http.Host   else "?"
            path   = http.Path.decode(errors="ignore")   if http.Path   else "?"
            out.console.print(f"[bold cyan]HTTP[/bold cyan]  {src} → {dst}:{dport}  [yellow]{method}[/yellow] http://{host}{path}")
            stats["HTTP"] += 1

        elif dport == 443 or sport == 443:
            out.console.print(f"[magenta]HTTPS[/magenta] {src}:{sport} → {dst}:{dport}  [dim](encrypted)[/dim]")
            stats["HTTPS"] += 1

        else:
            out.console.print(f"[blue]TCP[/blue]   {src}:{sport} → {dst}:{dport}")

        # Credential detection on raw payload
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            credentials = detect_credentials(payload)
            for label, value in credentials:
                out.console.print(f"  [bold red]⚠  CREDENTIAL FOUND[/bold red] — {label}: [bold]{value}[/bold]")
                stats["Credentials"] += 1

    # ── UDP ────────────────────────────────────────────────────────────
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        stats["UDP"] += 1

        # DNS detection (port 53)
        if pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            out.console.print(f"[green]DNS[/green]   {src} → {dst}  [yellow]query:[/yellow] {query}")
            stats["DNS"] += 1
        else:
            out.console.print(f"[blue]UDP[/blue]   {src}:{sport} → {dst}:{dport}")

    # ── ICMP ───────────────────────────────────────────────────────────
    elif pkt.haslayer(ICMP):
        stats["ICMP"] += 1
        out.console.print(f"[yellow]ICMP[/yellow]  {src} → {dst}  [dim](ping)[/dim]")


def show_interfaces():
    """List all network interfaces on the system."""
    out.console.print()
    out.console.rule("[bold magenta]Available Network Interfaces[/bold magenta]")
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces, 1):
        out.console.print(f"  {i}. {iface}")
    out.console.print()
    out.info("Use --iface <name> to choose. On Windows, names look like:")
    out.console.print("    \\Device\\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}")
    out.console.print("  Easiest: don't pass --iface, Scapy will auto-pick your main one.\n")


def main():
    parser = argparse.ArgumentParser(
        prog="sniffer",
        description="sec-toolkit packet sniffer — capture and analyse network traffic",
        epilog="Run as Administrator (Windows) or with sudo (Linux)."
    )
    parser.add_argument("--iface",   help="Network interface to capture on (omit for auto)")
    parser.add_argument("--filter",  default="", help="BPF filter (e.g. 'tcp port 80', 'udp port 53', 'icmp')")
    parser.add_argument("--count",   type=int, default=0, help="Stop after N packets (0 = unlimited, Ctrl+C to stop)")
    parser.add_argument("--output",  help="Save captured packets to a .pcap file (open in Wireshark)")
    parser.add_argument("--list-interfaces", action="store_true", help="List network interfaces and exit")
    args = parser.parse_args()

    out.banner("Packet Sniffer")

    if args.list_interfaces:
        show_interfaces()
        return

    out.info(f"Interface : {args.iface or 'auto-detect'}")
    out.info(f"Filter    : {args.filter or 'none (capturing everything)'}")
    out.info(f"Count     : {args.count if args.count else 'unlimited (Ctrl+C to stop)'}\n")

    out.console.rule("[bold magenta]Live Capture[/bold magenta]\n")

    # ── Start sniffing ─────────────────────────────────────────────────
    try:
        sniff(
            iface=args.iface,
            filter=args.filter or None,
            prn=process_packet,
            count=args.count,
            store=False,  # we store manually in captured_packets
        )
    except KeyboardInterrupt:
        out.console.print()
    except PermissionError:
        out.error("Permission denied. Run this script as Administrator (Windows) or sudo (Linux).")
        sys.exit(1)
    except OSError as e:
        out.error(f"Could not start capture: {e}")
        out.info("On Windows make sure Npcap is installed. On Linux check the interface exists.")
        sys.exit(1)

    # ── Summary ────────────────────────────────────────────────────────
    out.console.print()
    out.console.rule("[bold magenta]Capture Summary[/bold magenta]")
    out.success(f"Captured {len(captured_packets)} packets\n")

    for proto in ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "Credentials"]:
        if stats[proto]:
            color = "red" if proto == "Credentials" else "cyan"
            out.console.print(f"  [{color}]{proto:12s}[/{color}] {stats[proto]}")

    # ── Save PCAP ─────────────────────────────────────────────────────
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(path), captured_packets)
        out.console.print()
        out.success(f"PCAP saved → {path}")
        out.info("Open it in Wireshark for deeper analysis.")


if __name__ == "__main__":
    main()