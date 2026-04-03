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

### Day 5 — THM: Carnage Room (Emotet + Cobalt Strike)
- Completed: TryHackMe Carnage guided PCAP investigation
- New technique: TLS SNI hunting with tls.handshake.type==1 + time bounding
- New technique: Hex inspection for embedded zip content
- New technique: Cobalt Strike Host header masquerading detection
- New technique: SMTP forensics using frame contains "MAIL FROM"
- Pattern confirmed: api.ipify.org IP check seen in both Trickbot (Day 2) and Emotet (Day 5)
- Detection library: now 15 rules across 3 investigations
- New IOCs: 13 — domains, IPs, files, email addresses

### Day 6 — BazarLoader (TA551) PCAP Investigation

- Identified **BazarLoader infection via TA551 (Shathak) campaign** using HTTP payload delivery  
- Detected **malware retrieval pattern `/bmdff/`** — known signature used by TA551 campaigns  
- Extracted full victim profile:
  - Hostname: DESKTOP-KKITB6Q  
  - User: hobart.gunnarsson  
  - IP: 10.9.10.102  
  - MAC: 00:4f:49:b1:e8:c3  
- Identified **initial payload delivery over HTTP (port 80)**:
  - Domain: simpsonsavingss.com  
  - Payload: 64-bit BazarLoader DLL  
  - File size: ~284 KB  
- Extracted **SHA256 hash of malware sample** for threat intelligence correlation  
- Detected **C2 communication over HTTPS (port 443)**:
  - 167.172.37.9  
  - 94.158.245.52  
- Correlated traffic with **real-world sandbox analysis (ANY.RUN + Tria.ge)**  
- Confirmed infection chain:
  - Malspam → Word document → Macro execution → DLL download → C2 beaconing  
- Noted absence of:
  - Cobalt Strike  
  - DarkVNC  
  (indicating early-stage infection or incomplete execution chain)
- Mapped attack to **MITRE ATT&CK techniques**:
  - T1566 — Phishing (malspam delivery)  
  - T1204 — User Execution (macro-enabled document)  
  - T1105 — Ingress Tool Transfer (DLL download)  
  - T1071 — Application Layer Protocol (HTTPS C2)  
- Detection engineering insights:
  - `/bmdff/` URI pattern = **high-confidence detection signature**  
  - HTTP GET → DLL payload = **clear malware delivery indicator**  
  - Known campaign infrastructure can be correlated via Threat Intelligence  
- Strengthened ability to:
  - Combine **PCAP + sandbox + threat intelligence**  
  - Recognize **campaign-level patterns (TA551)**  
  - Write **real incident-style investigation reports**  
- First exposure to **campaign tracking (TA551)** and **malware family attribution (BazarLoader)**

### Key Concepts Learned This Week
- Beaconing detection via connection regularity analysis
- TLS SNI field reveals C2 domains without decryption
- HTTP response codes confirm payload delivery (200 OK = received)
- Data volume analysis — highest packet count = primary C2 channel
- MITRE ATT&CK mapping from raw packet observations

### Day 7 — Week 1 Wrap-up
- GitHub audit: all 4 investigation folders confirmed complete
- Detection library: 20 rules across 4 malware families
- Cold interview self-test: 10/10 questions answered
- Splunk: BOTS v1 dataset loaded and verified
- Status: READY FOR WEEK 2

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