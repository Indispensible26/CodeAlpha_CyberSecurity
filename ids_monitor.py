#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║       CodeAlpha Internship — Task 4: Network IDS                 ║
║       Python Lightweight Intrusion Detection System              ║
║       Author : Nwafor Bernard Offorbuike                         ║
╚══════════════════════════════════════════════════════════════════╝

Description:
    A Scapy-based, rule-driven IDS that monitors network traffic for
    suspicious activity including port scans, brute force, DoS, and
    web attacks. Generates structured alerts with severity levels
    and logs them in both human-readable and JSON formats.

Requirements:
    pip install scapy colorama
    Run as root/administrator.
"""

import sys
import os
import json
import datetime
import argparse
import threading
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR, conf
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
except ImportError as e:
    print(f"[ERROR] Missing dependency: {e}")
    print("Install with:  pip install scapy colorama")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────────────
BANNER = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║     CodeAlpha Cybersecurity Internship — Task 4: NIDS        ║
║        Lightweight Intrusion Detection System v1.0           ║
║        Author: Nwafor Bernard Offorbuike                     ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
ALERT_LOG   = os.path.join(LOG_DIR, f"ids_alerts_{TIMESTAMP}.log")
ALERT_JSON  = os.path.join(LOG_DIR, f"ids_alerts_{TIMESTAMP}.json")

# Alert severity levels
SEV_INFO     = "INFO"
SEV_LOW      = "LOW"
SEV_MEDIUM   = "MEDIUM"
SEV_HIGH     = "HIGH"
SEV_CRITICAL = "CRITICAL"

SEV_COLORS = {
    SEV_INFO:     Fore.CYAN,
    SEV_LOW:      Fore.GREEN,
    SEV_MEDIUM:   Fore.YELLOW,
    SEV_HIGH:     Fore.RED,
    SEV_CRITICAL: Back.RED + Fore.WHITE,
}


# ─────────────────────────────────────────────────────────────────
#  STATE TRACKING (for threshold/rate-based rules)
# ─────────────────────────────────────────────────────────────────
class TrafficTracker:
    """
    Tracks per-source packet rates, port access counts, and
    connection attempts within rolling time windows.
    """
    def __init__(self):
        self._lock       = threading.Lock()
        self.syn_counts  = defaultdict(list)    # src_ip -> [timestamps]
        self.port_hits   = defaultdict(set)     # src_ip -> {dst_ports}
        self.icmp_counts = defaultdict(list)
        self.ssh_counts  = defaultdict(list)
        self.dns_counts  = defaultdict(list)

    def record_syn(self, src_ip: str, now: float) -> int:
        with self._lock:
            self.syn_counts[src_ip].append(now)
            self.syn_counts[src_ip] = [t for t in self.syn_counts[src_ip] if now - t < 5]
            return len(self.syn_counts[src_ip])

    def record_port(self, src_ip: str, dst_port: int) -> int:
        with self._lock:
            self.port_hits[src_ip].add(dst_port)
            return len(self.port_hits[src_ip])

    def record_icmp(self, src_ip: str, now: float) -> int:
        with self._lock:
            self.icmp_counts[src_ip].append(now)
            self.icmp_counts[src_ip] = [t for t in self.icmp_counts[src_ip] if now - t < 5]
            return len(self.icmp_counts[src_ip])

    def record_ssh(self, src_ip: str, now: float) -> int:
        with self._lock:
            self.ssh_counts[src_ip].append(now)
            self.ssh_counts[src_ip] = [t for t in self.ssh_counts[src_ip] if now - t < 30]
            return len(self.ssh_counts[src_ip])

    def record_dns(self, src_ip: str, now: float) -> int:
        with self._lock:
            self.dns_counts[src_ip].append(now)
            self.dns_counts[src_ip] = [t for t in self.dns_counts[src_ip] if now - t < 10]
            return len(self.dns_counts[src_ip])


tracker = TrafficTracker()
alert_store = []   # All alerts, for JSON export
alert_counts = defaultdict(int)


# ─────────────────────────────────────────────────────────────────
#  ALERT SYSTEM
# ─────────────────────────────────────────────────────────────────
def raise_alert(severity: str, rule_name: str, src_ip: str,
                dst_ip: str, proto: str, detail: str = ""):
    """Log and display a triggered IDS alert."""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    color = SEV_COLORS.get(severity, Fore.WHITE)
    alert_counts[severity] += 1

    # Terminal output
    sep = f"{color}{'━' * 68}{Style.RESET_ALL}"
    print(f"\n{sep}")
    print(f"{color}  🚨 ALERT [{severity}] — {rule_name}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Time    :{Style.RESET_ALL} {ts}")
    print(f"  {Fore.WHITE}Protocol:{Style.RESET_ALL} {proto:<8}  "
          f"{Fore.WHITE}Src:{Style.RESET_ALL} {src_ip:<18}  "
          f"{Fore.WHITE}Dst:{Style.RESET_ALL} {dst_ip}")
    if detail:
        print(f"  {Fore.WHITE}Detail  :{Style.RESET_ALL} {detail}")
    print(sep)

    # Log to file
    log_entry = (f"[{ts}] [{severity}] {rule_name} | "
                 f"Proto:{proto} Src:{src_ip} Dst:{dst_ip} | {detail}\n")
    with open(ALERT_LOG, "a") as f:
        f.write(log_entry)

    # JSON store
    record = {
        "timestamp": ts,
        "severity":  severity,
        "rule":      rule_name,
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "protocol":  proto,
        "detail":    detail,
    }
    alert_store.append(record)

    # Write JSON incrementally
    with open(ALERT_JSON, "w") as f:
        json.dump(alert_store, f, indent=2)


# ─────────────────────────────────────────────────────────────────
#  DETECTION RULES
# ─────────────────────────────────────────────────────────────────
def check_port_scan(pkt, src_ip, dst_ip, now):
    """Detect TCP SYN port scans — many unique ports in short time."""
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        dst_port = pkt[TCP].dport
        syn_rate = tracker.record_syn(src_ip, now)
        unique_ports = tracker.record_port(src_ip, dst_port)

        if syn_rate > 20:
            raise_alert(SEV_HIGH, "TCP SYN Port Scan Detected", src_ip, dst_ip,
                        "TCP", f"{syn_rate} SYN packets in 5s from same source")
        if unique_ports > 15:
            raise_alert(SEV_CRITICAL, "Multi-Port Scan — Possible Recon", src_ip, dst_ip,
                        "TCP", f"{unique_ports} unique destination ports contacted")


def check_null_xmas_scan(pkt, src_ip, dst_ip):
    """Detect TCP NULL and XMAS scan flag patterns."""
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        if flags == 0:
            raise_alert(SEV_HIGH, "TCP NULL Scan Detected", src_ip, dst_ip,
                        "TCP", "Packet with no TCP flags set")
        elif flags == 0x29:  # FIN + PSH + URG
            raise_alert(SEV_HIGH, "TCP XMAS Scan Detected", src_ip, dst_ip,
                        "TCP", "FIN+PSH+URG flags — likely XMAS scan")


def check_icmp_flood(pkt, src_ip, dst_ip, now):
    """Detect ICMP flood / Ping of Death."""
    if pkt.haslayer(ICMP):
        rate = tracker.record_icmp(src_ip, now)
        if rate > 60:
            raise_alert(SEV_CRITICAL, "ICMP Flood (DoS) Detected", src_ip, dst_ip,
                        "ICMP", f"{rate} ICMP packets in 5s")
        if len(pkt) > 1500:
            raise_alert(SEV_HIGH, "Oversized ICMP Packet (Ping of Death)", src_ip, dst_ip,
                        "ICMP", f"Packet size: {len(pkt)} bytes")


def check_ssh_brute(pkt, src_ip, dst_ip, now):
    """Detect SSH brute force connection attempts."""
    if pkt.haslayer(TCP) and pkt[TCP].dport == 22 and pkt[TCP].flags == "S":
        rate = tracker.record_ssh(src_ip, now)
        if rate > 5:
            raise_alert(SEV_HIGH, "SSH Brute Force Detected", src_ip, dst_ip,
                        "TCP", f"{rate} SSH connection attempts in 30s")


def check_web_attacks(pkt, src_ip, dst_ip):
    """Detect SQL injection, XSS, and directory traversal in HTTP payloads."""
    if not pkt.haslayer(Raw):
        return
    try:
        payload = pkt[Raw].load.decode("utf-8", errors="replace").lower()
    except Exception:
        return

    # Only inspect HTTP-ish traffic
    if pkt.haslayer(TCP) and pkt[TCP].dport not in (80, 8080, 8000, 443):
        return

    sqli_patterns = ["union select", "or 1=1", "drop table", "insert into",
                     "' or '", "' and '", "1' or '1'='1", "sleep(", "benchmark("]
    xss_patterns  = ["<script>", "javascript:", "onerror=", "onload=", "eval("]
    trav_patterns = ["../", "..\\", "%2e%2e/", "%252e%252e/"]

    for p in sqli_patterns:
        if p in payload:
            raise_alert(SEV_CRITICAL, "SQL Injection Attempt", src_ip, dst_ip,
                        "HTTP", f"Pattern: '{p}'")
            return

    for p in xss_patterns:
        if p in payload:
            raise_alert(SEV_HIGH, "XSS Attempt Detected", src_ip, dst_ip,
                        "HTTP", f"Pattern: '{p}'")
            return

    for p in trav_patterns:
        if p in payload:
            raise_alert(SEV_HIGH, "Directory Traversal Attempt", src_ip, dst_ip,
                        "HTTP", f"Pattern: '{p}'")
            return


def check_reverse_shell(pkt, src_ip, dst_ip):
    """Detect common reverse shell payloads."""
    if not pkt.haslayer(Raw):
        return
    try:
        payload = pkt[Raw].load.decode("utf-8", errors="replace").lower()
    except Exception:
        return

    shell_patterns = ["/bin/bash", "/bin/sh", "cmd.exe /c", "powershell -enc",
                      "nc -e /bin/", "bash -i >& /dev/tcp"]
    for p in shell_patterns:
        if p in payload:
            raise_alert(SEV_CRITICAL, "Possible Reverse Shell Payload", src_ip, dst_ip,
                        "TCP", f"Pattern: '{p}'")
            return


def check_dns_tunnelling(pkt, src_ip, dst_ip, now):
    """Detect high-frequency DNS queries (DNS tunnelling / beaconing)."""
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        rate = tracker.record_dns(src_ip, now)
        if rate > 40:
            raise_alert(SEV_HIGH, "Possible DNS Tunnelling / Beaconing", src_ip, dst_ip,
                        "DNS", f"{rate} DNS queries in 10s from same source")


def check_telnet(pkt, src_ip, dst_ip):
    """Alert on Telnet — unencrypted remote access."""
    if pkt.haslayer(TCP) and pkt[TCP].dport == 23 and pkt[TCP].flags == "S":
        raise_alert(SEV_MEDIUM, "Telnet Access Attempt (Cleartext Protocol)", src_ip, dst_ip,
                    "TCP", "Port 23 — consider SSH instead")


def check_suspicious_ports(pkt, src_ip, dst_ip):
    """Monitor known C2/RAT ports."""
    c2_ports = {4444: "Metasploit Meterpreter", 1234: "Common RAT port",
                6666: "Common C2 port", 31337: "Back Orifice / Elite"}
    if pkt.haslayer(TCP):
        port = pkt[TCP].dport
        if port in c2_ports:
            raise_alert(SEV_HIGH, f"Suspicious C2 Port — {c2_ports[port]}",
                        src_ip, dst_ip, "TCP", f"Connection to port {port}")


# ─────────────────────────────────────────────────────────────────
#  MAIN PACKET HANDLER
# ─────────────────────────────────────────────────────────────────
packet_total = 0

def inspect_packet(pkt):
    global packet_total
    packet_total += 1

    if not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    now = datetime.datetime.now().timestamp()

    # Run all detection rules
    check_port_scan(pkt, src_ip, dst_ip, now)
    check_null_xmas_scan(pkt, src_ip, dst_ip)
    check_icmp_flood(pkt, src_ip, dst_ip, now)
    check_ssh_brute(pkt, src_ip, dst_ip, now)
    check_web_attacks(pkt, src_ip, dst_ip)
    check_reverse_shell(pkt, src_ip, dst_ip)
    check_dns_tunnelling(pkt, src_ip, dst_ip, now)
    check_telnet(pkt, src_ip, dst_ip)
    check_suspicious_ports(pkt, src_ip, dst_ip)

    # Progress indicator every 100 packets
    if packet_total % 100 == 0:
        total_alerts = sum(alert_counts.values())
        print(f"\r  {Fore.CYAN}[Packets: {packet_total} | Alerts: {total_alerts}]{Style.RESET_ALL}",
              end="", flush=True)


# ─────────────────────────────────────────────────────────────────
#  SUMMARY REPORT
# ─────────────────────────────────────────────────────────────────
def print_summary():
    print(f"\n\n{Fore.RED}{'═' * 60}")
    print("  IDS SESSION SUMMARY")
    print(f"{'═' * 60}{Style.RESET_ALL}")
    print(f"  Total packets inspected : {packet_total}")
    print(f"  Total alerts generated  : {sum(alert_counts.values())}")
    print()
    order = [SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO]
    for sev in order:
        count = alert_counts[sev]
        if count > 0:
            color = SEV_COLORS[sev]
            bar = "█" * min(count, 30)
            print(f"  {color}{sev:<10}{Style.RESET_ALL} : {count:>4}  {Fore.RED}{bar}{Style.RESET_ALL}")
    print()
    print(f"  {Fore.YELLOW}Alert log : {ALERT_LOG}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}JSON data : {ALERT_JSON}{Style.RESET_ALL}")
    print()


# ─────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="CodeAlpha Task 4 — Lightweight Python IDS"
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface to monitor (default: auto)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter", default="ip",
                        help="BPF filter (default: 'ip')")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print(f"{Fore.YELLOW}[!] Not running as root — may fail. Try: sudo python3 ids_monitor.py{Style.RESET_ALL}\n")

    print(f"{Fore.GREEN}[*] IDS started.")
    print(f"    Interface : {args.interface or 'auto-detect'}")
    print(f"    Count     : {'unlimited' if args.count == 0 else args.count}")
    print(f"    Filter    : '{args.filter}'")
    print(f"    Alert log : {ALERT_LOG}")
    print(f"    JSON log  : {ALERT_JSON}")
    print(f"\n    Active detection rules:")
    rules = [
        "Port Scan (SYN flood, NULL, XMAS)",
        "ICMP Flood / Ping of Death",
        "SSH Brute Force",
        "SQL Injection (HTTP payloads)",
        "XSS Attacks",
        "Directory Traversal",
        "Reverse Shell Payloads",
        "DNS Tunnelling / Beaconing",
        "Telnet Usage",
        "Suspicious C2 Ports (4444, 1234, 6666, 31337)",
    ]
    for r in rules:
        print(f"      {Fore.GREEN}✔{Style.RESET_ALL} {r}")
    print(f"\n    {Fore.YELLOW}Press Ctrl+C to stop and view summary.{Style.RESET_ALL}\n")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=inspect_packet,
            count=args.count,
            store=False,
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print(f"\n{Fore.RED}[!] Permission denied. Run with sudo.{Style.RESET_ALL}")
    finally:
        print_summary()


if __name__ == "__main__":
    main()
