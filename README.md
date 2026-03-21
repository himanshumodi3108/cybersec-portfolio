# Cybersecurity Portfolio — SOC Analyst / DFIR

**Himanshu Kumar Modi**
📍 Mumbai, India | 🔗 [LinkedIn Profile](www.linkedin.com/in/himanshu-kumar-modi-063b88239) | 💻 [GitHub Profile](https://github.com/himanshumodi3108)

---

## Certifications

| Certification | Issuer | Status |
|---|---|---|
| Google Cybersecurity Certificate | Google / Coursera | ✅ Complete |
| Certified in Cybersecurity (CC) | ISC2 | ✅ Complete |
| Blue Team Level 1 (BTL1) | Security Blue Team | 🔄 In Progress |

---

## Technical Skills

| Category | Tools & Skills |
|---|---|
| Network Forensics | Wireshark, PCAP analysis, IOC extraction, beaconing detection |
| SIEM | Splunk SPL, log correlation, threat hunting, BOTS dataset |
| Endpoint Forensics | Autopsy, Eric Zimmerman Tools (PECmd, JLECmd, Registry Explorer) |
| Memory Forensics | Volatility 3 (pslist, netscan, malfind, cmdline) |
| Malware Analysis | PEStudio, ANY.RUN, REMnux, static + dynamic analysis |
| Threat Intel | MITRE ATT&CK mapping, ATT&CK Navigator, VirusTotal |
| Incident Response | NIST SP 800-61, IR playbooks, phishing analysis |
| Languages | Python, Bash(Basic), PowerShell (basic) |

---

## Projects

### 01 — Network Forensics: Ursnif Malware Investigation
**Status:** ✅ Complete
Analyzed a real Ursnif/Gozi banking trojan PCAP. Reconstructed full infection chain from macro execution → payload download → C2 beaconing. Extracted 10 IOCs and wrote 5 Splunk detection rules.
→ [report.md](01-network-forensics/01_report.md)

### 02 — Network Forensics: Trickbot Infostealer
**Status:** ✅ Complete
Analyzed Trickbot infostealer PCAP. Caught live credential exfiltration — 5 compromised accounts (Google, Facebook, Yahoo) in plaintext POST body. Identified non-standard port 447 C2 evasion, fake IE7 User-Agent, and bot ID fingerprinting. Wrote 5 detection rules including zero-false-positive User-Agent signature.
→ [report.md](02-network-forensics-trickbot/02_report.md)

---

## Detection Query Library

A growing collection of Splunk SPL detection rules built from real lab investigations.
→ [detection-queries-library.md](detection-queries-library.md)

| Week | Rules Added | Source |
|---|---|---|
| Week 1 | 10 rules | Ursnif PCAP (5) + Trickbot PCAP (5) — beaconing, credential exfil, port evasion, User-Agent masquerade |

---

## Weekly Progress Log

| Week | Focus | Status |
|---|---|---|
| Week 1 | Wireshark — Analyst-level PCAP investigation | ✅ Complete — 2 PCAPs, 10 IOCs, 10 detection rules |
| Week 2 | Splunk SPL + BOTS v1 start | 🔜 Starts Day 8 |
| Week 3 | BOTS v1 finish + Windows Forensics | 🔜 Upcoming |
| Week 4 | Memory Forensics — Volatility 3 | 🔜 Upcoming |
| Week 5 | Malware Analysis — Static + Dynamic | 🔜 Upcoming |
| Week 6 | BTL1 Prep + Phishing Analysis | 🔜 Upcoming |
| Week 7 | BTL1 Exam + Write-ups | 🔜 Upcoming |
| Week 8 | Applications | 🔜 Upcoming |

---

*Updated weekly. All investigations use real malware datasets and industry-standard tools.*