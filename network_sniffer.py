#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          CodeAlpha Internship — Task 1: Network Sniffer      ║
║          Author : Nwafor Bernard Offorbuike                   ║
║          Tool   : Scapy-based Packet Capture & Analyzer       ║
╚══════════════════════════════════════════════════════════════╝

Description:
    Captures live network packets and displays structured information
    including source/destination IPs, protocols, ports, and payloads.
    Supports optional filtering by protocol (TCP, UDP, ICMP, ARP).
    Logs all captured packets to a timestamped file for review.

Requirements:
    pip install scapy colorama
    Run as root/administrator for raw packet capture.
"""

import sys
import os
import datetime
import argparse
from collections import defaultdict

# --- Dependency check ---
try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR,
        Raw, Ether, get_if_list, conf
    )
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError as e:
    print(f"[ERROR] Missing dependency: {e}")
    print("Install with:  pip install scapy colorama")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────────────
BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║      CodeAlpha Cybersecurity Internship — Task 1         ║
║           Basic Network Sniffer v1.0                     ║
║      Author: Nwafor Bernard Offorbuike                   ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = os.path.join(LOG_DIR, f"capture_{TIMESTAMP}.log")

# Counters for summary
stats = defaultdict(int)
packet_count = 0


# ─────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────
def log(message: str):
    """Write message to log file."""
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")


def format_payload(payload: bytes, max_len: int = 80) -> str:
    """Return a safe, readable representation of raw payload bytes."""
    try:
        decoded = payload.decode("utf-8", errors="replace")
        text = decoded[:max_len]
    except Exception:
        text = repr(payload[:max_len])
    return text.replace("\n", " ").replace("\r", "")


def get_protocol_name(pkt) -> str:
    """Determine the highest-level protocol in the packet."""
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(ARP):
        return "ARP"
    return "OTHER"


def protocol_color(proto: str) -> str:
    colors = {
        "TCP":   Fore.GREEN,
        "UDP":   Fore.YELLOW,
        "ICMP":  Fore.MAGENTA,
        "ARP":   Fore.CYAN,
        "DNS":   Fore.BLUE,
        "OTHER": Fore.WHITE,
    }
    return colors.get(proto, Fore.WHITE)


# ─────────────────────────────────────────────────────────────────
#  PACKET CALLBACK
# ─────────────────────────────────────────────────────────────────
def process_packet(pkt):
    """Callback invoked for every captured packet."""
    global packet_count
    packet_count += 1

    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    proto = get_protocol_name(pkt)
    stats[proto] += 1
    color = protocol_color(proto)

    # ── Layer 2: Ethernet ─────────────────────────────────────────
    src_mac = dst_mac = "N/A"
    if pkt.haslayer(Ether):
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst

    # ── Layer 3: IP ───────────────────────────────────────────────
    src_ip = dst_ip = "N/A"
    ttl = "N/A"
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ttl    = pkt[IP].ttl

    # ── Layer 4: TCP / UDP ────────────────────────────────────────
    src_port = dst_port = flags = "N/A"
    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flags    = str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    # ── ICMP ──────────────────────────────────────────────────────
    icmp_type = icmp_code = "N/A"
    if pkt.haslayer(ICMP):
        icmp_type = pkt[ICMP].type
        icmp_code = pkt[ICMP].code

    # ── ARP ───────────────────────────────────────────────────────
    arp_op = "N/A"
    if pkt.haslayer(ARP):
        arp_op  = "Request" if pkt[ARP].op == 1 else "Reply"
        src_ip  = pkt[ARP].psrc
        dst_ip  = pkt[ARP].pdst
        src_mac = pkt[ARP].hwsrc

    # ── DNS ───────────────────────────────────────────────────────
    dns_query = "N/A"
    if pkt.haslayer(DNSQR):
        dns_query = pkt[DNSQR].qname.decode("utf-8", errors="replace")

    # ── Payload ───────────────────────────────────────────────────
    payload_text = "N/A"
    if pkt.haslayer(Raw):
        payload_text = format_payload(pkt[Raw].load)

    # ── Packet Size ───────────────────────────────────────────────
    pkt_len = len(pkt)

    # ── Build display string ──────────────────────────────────────
    separator = f"{color}{'─' * 70}{Style.RESET_ALL}"
    header    = (f"{color}[#{packet_count:04d}] [{timestamp}] "
                 f"Protocol: {proto:<6} | Size: {pkt_len} bytes{Style.RESET_ALL}")

    lines = [separator, header]

    # IP info
    if src_ip != "N/A":
        lines.append(f"  {Fore.WHITE}SRC IP   :{Style.RESET_ALL} {src_ip:<20}  "
                     f"{Fore.WHITE}DST IP :{Style.RESET_ALL} {dst_ip}  TTL: {ttl}")

    # MAC info
    if src_mac != "N/A":
        lines.append(f"  {Fore.WHITE}SRC MAC  :{Style.RESET_ALL} {src_mac:<20}  "
                     f"{Fore.WHITE}DST MAC:{Style.RESET_ALL} {dst_mac}")

    # Ports / Flags
    if src_port != "N/A":
        lines.append(f"  {Fore.WHITE}SRC PORT :{Style.RESET_ALL} {str(src_port):<20}  "
                     f"{Fore.WHITE}DST PORT:{Style.RESET_ALL} {dst_port}")
    if flags != "N/A":
        lines.append(f"  {Fore.WHITE}TCP FLAGS :{Style.RESET_ALL} {flags}")

    # ICMP
    if icmp_type != "N/A":
        lines.append(f"  {Fore.WHITE}ICMP Type:{Style.RESET_ALL} {icmp_type}   "
                     f"{Fore.WHITE}Code:{Style.RESET_ALL} {icmp_code}")

    # ARP
    if arp_op != "N/A":
        lines.append(f"  {Fore.WHITE}ARP Op   :{Style.RESET_ALL} {arp_op}")

    # DNS
    if dns_query != "N/A":
        lines.append(f"  {Fore.WHITE}DNS Query:{Style.RESET_ALL} {dns_query}")

    # Payload
    if payload_text != "N/A":
        lines.append(f"  {Fore.WHITE}Payload  :{Style.RESET_ALL} "
                     f"{Fore.YELLOW}{payload_text}{Style.RESET_ALL}")

    output = "\n".join(lines)
    print(output)
    log(output)  # also write to file (strip color codes would be ideal in prod)


# ─────────────────────────────────────────────────────────────────
#  SUMMARY
# ─────────────────────────────────────────────────────────────────
def print_summary():
    print(f"\n{Fore.CYAN}{'═' * 55}")
    print(f"  CAPTURE SUMMARY")
    print(f"{'═' * 55}{Style.RESET_ALL}")
    print(f"  Total packets captured : {packet_count}")
    for proto, count in sorted(stats.items(), key=lambda x: -x[1]):
        bar = "█" * min(count, 40)
        print(f"  {proto:<8} : {count:>5}  {Fore.GREEN}{bar}{Style.RESET_ALL}")
    print(f"\n  {Fore.YELLOW}Log saved to: {LOG_FILE}{Style.RESET_ALL}\n")


# ─────────────────────────────────────────────────────────────────
#  INTERFACE LISTING
# ─────────────────────────────────────────────────────────────────
def list_interfaces():
    print(f"\n{Fore.CYAN}Available Network Interfaces:{Style.RESET_ALL}")
    for i, iface in enumerate(get_if_list()):
        print(f"  [{i}] {iface}")
    print()


# ─────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="CodeAlpha Task 1 — Basic Network Sniffer"
    )
    parser.add_argument(
        "-i", "--interface",
        default=None,
        help="Network interface to sniff on (e.g., eth0, wlan0). Default: auto-detect."
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited). Default: 0."
    )
    parser.add_argument(
        "-f", "--filter",
        default="",
        help="BPF filter string (e.g., 'tcp', 'udp port 53', 'icmp'). Default: all traffic."
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List all available network interfaces and exit."
    )
    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    # Privilege check
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Warning: Not running as root. "
              f"Packet capture may be limited or fail.\n"
              f"    Try:  sudo python3 network_sniffer.py{Style.RESET_ALL}\n")

    iface = args.interface
    count = args.count
    bpf   = args.filter

    print(f"{Fore.GREEN}[*] Starting capture...")
    print(f"    Interface : {iface or 'auto-detect'}")
    print(f"    Count     : {'unlimited' if count == 0 else count}")
    print(f"    BPF Filter: '{bpf}' (empty = all)")
    print(f"    Log File  : {LOG_FILE}")
    print(f"    Press Ctrl+C to stop.{Style.RESET_ALL}\n")

    try:
        sniff(
            iface=iface,
            filter=bpf,
            prn=process_packet,
            count=count,
            store=False      # don't store in memory — saves RAM for long runs
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print(f"\n{Fore.RED}[!] Permission denied. Run with sudo/root.{Style.RESET_ALL}")
    finally:
        print_summary()


if __name__ == "__main__":
    main()
