# Learning Log

## Week 1 — Network Forensics (Days 1–7)

### Day 1 — Ursnif/Gozi PCAP Analysis
- Reconstructed 6-stage infection chain from macro execution to C2 beaconing
- Extracted 10 IOCs — 4 IPs, 3 domains, 3 file indicators
- Identified .avi extension used to disguise DLL payloads (T1027)
- Wrote 5 Splunk SPL detection rules

### Day 2 — Trickbot Infostealer PCAP Analysis
- Caught live credential exfiltration — 5 accounts compromised (Google, Facebook, Yahoo)
- Identified HTTP on port 443 (not TLS) — deliberate attacker evasion technique
- Decoded Trickbot bot ID structure embedded in POST URI
- Detected port 447 non-standard C2 channel (T1571)
- Wrote 5 Splunk SPL detection rules including zero-false-positive User-Agent signature

### Key Concepts Learned This Week
- Beaconing detection via connection regularity analysis
- TLS SNI field reveals C2 domains without decryption
- HTTP response codes confirm payload delivery (200 OK = received)
- Data volume analysis — highest packet count = primary C2 channel
- MITRE ATT&CK mapping from raw packet observations

---

## Week 2 — Splunk + BOTS v1 (Days 8–14)
*In progress — starts Day 8*

---

## Week 3 — Windows Forensics (Days 15–21)
*Upcoming*

---

## Week 4 — Memory Forensics — Volatility 3 (Days 22–28)
*Upcoming*

---

## Week 5 — Malware Analysis — Static + Dynamic (Days 29–35)
*Upcoming*

---

## Week 6 — BTL1 Prep + Phishing Analysis (Days 36–42)
*Upcoming*

---

## Week 7 — BTL1 Exam + Write-ups (Days 43–49)
*Upcoming*

---

## Week 8 — Applications (Days 50–56)
*Upcoming*