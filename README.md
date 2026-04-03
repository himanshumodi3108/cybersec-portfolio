# SOC Analyst | Digital Forensics | Threat Detection | Incident Response

> Hands-on cybersecurity portfolio built from real malware investigations, live credential theft analysis, and SIEM detection engineering. Updated weekly.

**Himanshu Kumar Modi**
📍 Mumbai, India | 🔗 [LinkedIn Profile](https://www.linkedin.com/in/himanshu-kumar-modi-063b88239) | 💻 [GitHub Profile](https://github.com/himanshumodi3108)

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

### 03 — THM: Carnage Room (Emotet + Cobalt Strike)
**Status:** ✅ Complete
Analyzed network traffic to investigate a malware infection involving file download, C2 communication, and data exfiltration.
→ [report.md](03-thm-carnage/05_report.md)

### 04 — Network Forensics: BazarLoader (TA551) Malware Investigation
**Status:** ✅ Complete  
Analyzed BazarLoader infection PCAP from TA551 (Shathak) campaign. Identified HTTP-based DLL payload delivery using `/bmdff/` URI pattern and extracted SHA256 hash. Correlated traffic with sandbox analysis (ANY.RUN, Tria.ge) and confirmed infection chain: malspam → macro execution → DLL download → HTTPS C2 beaconing. Extracted victim profile, 3+ IOCs, and mapped activity to MITRE ATT&CK techniques.  
→ [report.md](04-network-forensics-bazarloader/06_report.md)

---

## 💼 Portfolio Highlights

- Investigated real-world malware PCAPs and reconstructed full infection chains
- Detected live credential exfiltration via HTTP POST stream analysis (Trickbot)
- Extracted and documented IOCs across 2 malware families — 20 total indicators
- Mapped attacker behavior to MITRE ATT&CK framework across 9 technique IDs
- Wrote 20 Splunk SPL detection rules from observed malware behaviors
- Identified evasion techniques: payload disguise, non-standard ports, User-Agent spoofing

---

## 🧰 Tools Proficiency

| Tool | Level | Used For |
|---|---|---|
| Wireshark | Advanced | PCAP analysis, IOC extraction, stream following, beaconing detection |
| Splunk SPL | Intermediate | Log correlation, threat hunting, detection rule writing, BOTS dataset |
| MITRE ATT&CK | Intermediate | TTP mapping, Navigator layer building, detection alignment |
| Volatility 3 | Beginner | Memory forensics — pslist, netscan, malfind, cmdline |
| Autopsy | Beginner | Disk forensics, deleted file recovery, artifact analysis |
| EZ Tools | Beginner | Registry Explorer, PECmd, JLECmd — Windows artifact parsing |
| PEStudio | Beginner | Static malware analysis — PE headers, imports, entropy |
| ANY.RUN | Beginner | Dynamic malware sandboxing |
| VirusTotal | Intermediate | Hash/domain/IP reputation, malware family identification |
| Nmap | Intermediate | Port scanning, OS fingerprinting, network enumeration |
| Metasploit | Basic | Exploitation framework, payload delivery (academic) |

---

## 🔍 Detection Strategy

Every investigation in this portfolio follows a three-step detection methodology:

1. **Find** — identify the attack behavior using forensic tools
2. **Map** — assign MITRE ATT&CK technique IDs to each behavior
3. **Detect** — write the Splunk SPL rule that would catch it in production

This approach ensures every project produces actionable detection logic, not just observations.

---

## 🎯 SOC Analyst Focus Areas
```
Credential Theft Detection    →  HTTP POST analysis, browser data exfiltration monitoring
C2 Communication Detection    →  Beaconing regularity, non-standard ports, SNI monitoring  
Payload Delivery Detection    →  File extension mismatch, chunked downloads, archive names
Evasion Technique Detection   →  User-Agent anomalies, port 443 HTTP, DGA patterns
Incident Response             →  NIST SP 800-61 lifecycle, containment actions, IOC blocking
```
---

## Detection Query Library

A growing collection of Splunk SPL detection rules built from real lab investigations.
→ [detection-queries-library.md](detection-queries-library.md)

| Week | Rules Added | Source |
|---|---|---|
| Week 1 | 20 rules | Ursnif PCAP (5) + Trickbot PCAP (5) — beaconing, credential exfil, port evasion, User-Agent masquerade + THM: Carnage (5) + Bazarloader PCAP(5)|

---

## Weekly Progress Log

| Week | Focus | Status |
|---|---|---|
| Week 1 | Wireshark — Analyst-level PCAP investigation | ✅ Complete — 4 PCAPs, 10 IOCs, 20 detection rules |
| Week 2 | Splunk SPL + BOTS v1 start | 🔜 Starts Day 8 |
| Week 3 | BOTS v1 finish + Windows Forensics | 🔜 Upcoming |
| Week 4 | Memory Forensics — Volatility 3 | 🔜 Upcoming |
| Week 5 | Malware Analysis — Static + Dynamic | 🔜 Upcoming |
| Week 6 | BTL1 Prep + Phishing Analysis | 🔜 Upcoming |
| Week 7 | BTL1 Exam + Write-ups | 🔜 Upcoming |
| Week 8 | Applications | 🔜 Upcoming |

---

*Updated weekly. All investigations use real malware datasets and industry-standard tools.*