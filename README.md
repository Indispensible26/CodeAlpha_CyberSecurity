# CodeAlpha Cybersecurity Internship 

**Intern:** Nwafor Bernard Offorbuike  
**Programme:** CodeAlpha Cybersecurity Internship  
**Website:** [www.codealpha.tech](https://www.codealpha.tech)

---

## Completed Tasks

| Task | Title | Technologies |
|------|-------|-------------|
| [Task 1](./Task1_NetworkSniffer/) | Basic Network Sniffer | Python, Scapy, Colorama |
| [Task 2](./Task2_PhishingAwareness/) | Phishing Awareness Training | HTML, CSS, JavaScript |
| [Task 4](./Task4_NIDS/) | Network Intrusion Detection System | Python, Scapy, Snort, HTML |

---

## Task Summaries

### 🔍 Task 1 — Basic Network Sniffer
A Python packet sniffer that captures live network traffic using Scapy. Displays source/destination IPs, MAC addresses, ports, TCP flags, DNS queries, and raw payloads in a color-coded terminal output. Supports BPF filtering and auto-logs to timestamped files.

### 🎣 Task 2 — Phishing Awareness Training
A fully interactive, browser-based security awareness module with 7 sections: Introduction, Red Flag Recognition, Annotated Phishing Email Demo, Social Engineering Tactics, Best Practices, URL Suspicion Analyser, and a 6-question quiz with instant scoring feedback.

### 🛡️ Task 4 — Network Intrusion Detection System
A dual-approach NIDS consisting of a Python/Scapy IDS engine (14 active detection rules spanning port scans, brute force, web attacks, malware C2, and DoS), a custom Snort rules file (30+ rules), and a browser-based alert visualisation dashboard with charts and CSV export.

---

## Repository Structure

```
CodeAlpha_CyberSecurity/
├── Task1_NetworkSniffer/
│   ├── network_sniffer.py
│   └── README.md
├── Task2_PhishingAwareness/
│   ├── phishing_awareness.html
│   └── README.md
├── Task4_NIDS/
│   ├── ids_monitor.py
│   ├── ids_dashboard.html
│   ├── snort_rules/
│   │   └── local.rules
│   └── README.md
└── README.md
```

---

## Quick Start

### Task 1
```bash
cd Task1_NetworkSniffer
pip install scapy colorama
sudo python3 network_sniffer.py
```

### Task 2
```bash
cd Task2_PhishingAwareness
# Open phishing_awareness.html in any browser
```

### Task 4
```bash
cd Task4_NIDS
pip install scapy colorama
sudo python3 ids_monitor.py
# Open ids_dashboard.html to visualise alerts
```

---

*All tools are for educational use only. Only run on networks you own or have explicit authorisation to monitor.*
