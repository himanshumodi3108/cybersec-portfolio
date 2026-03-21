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