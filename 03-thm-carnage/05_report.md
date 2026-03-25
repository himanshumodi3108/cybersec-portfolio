# THM Room Walkthrough — Carnage
## Guided PCAP Investigation | Emotet + Cobalt Strike
**Date:** 2026-03-24
**Analyst:** Himanshu Kumar Modi
**Platform:** TryHackMe — Carnage Room
**Room type:** Guided PCAP investigation with scored questions
**Certifications:** Google Cybersecurity Certificate | ISC2 CC

---

## Room Overview

The Carnage room presents a real-world attack scenario involving a multi-stage infection chain: an Emotet-style malware delivery via a malicious zip file, followed by Cobalt Strike C2 beacon establishment and post-infection malspam activity. This room reinforces analyst methodology across HTTP analysis, TLS SNI hunting, VirusTotal correlation, and SMTP forensics.

---

## Investigation Findings

### Q1 — First HTTP Connection to Malicious IP
**Filter used:** `http`
**Method:** Sorted by time, checked first frame details

**Answer:** `2021-09-24 16:44:38 UTC`

**Analyst note:** Setting Wireshark's time display to UTC (View → Time Display Format → UTC) before starting any investigation is essential for accurate timeline reconstruction. All timestamps in incident reports must be UTC.

---

### Q2 — Malicious Zip File Name
**Filter used:** `http.request.method == "GET"`
**Frame:** 1735 — first HTTP GET request

**Answer:** `documents.zip`

**Analyst note:** The first HTTP GET in a malware PCAP is almost always the initial payload delivery. Always examine Frame 1 of any HTTP conversation before applying complex filters.

---

### Q3 — Domain Hosting the Malicious Zip
**Method:** Examined frame details → Hypertext Transfer Protocol section → URI field

**Answer:** `attirenepal.com`

**Analyst note:** The Host header in an HTTP GET request reveals the domain even when traffic is not TLS-encrypted. This domain would be your first DNS block entry in an IR response.

---

### Q4 — Filename Inside the Zip (Without Downloading)
**Method:** Examined HTTP response packet (Frame 2173) → checked hex view at end of packet

**Answer:** `chart-1530076591.xls`

**Key technique learned — Hex inspection for embedded filenames:**
When a file is transferred over HTTP, its internal structure (including filenames in zip archives) is often visible in the raw hex of the response packet. Checking the end of the hex view first is faster than scanning from the beginning — zip file central directory entries are stored at the end of the archive.

The `.xls` extension indicates a malicious Excel file — consistent with Emotet's macro-based delivery mechanism.

---

### Q5 — Web Server of the Malicious IP
**Method:** HTTP response frame → Hypertext Transfer Protocol section → `Server:` header

**Answer:** `LiteSpeed`

---

### Q6 — Web Server Version
**Method:** Same HTTP response frame → `X-Powered-By:` header

**Answer:** `PHP/7.2.34`

**Analyst note:** Web server version information is valuable threat intelligence — it confirms the attacker's infrastructure and can be correlated with known bulletproof hosting providers.

---

### Q7 — Three Domains Delivering Malicious Files
**Filter used:** `tls.handshake.type == 1` (TLS Client Hello — reveals SNI in plaintext)
**Time range:** `16:45:11 to 16:45:30 UTC` (post initial infection window)
**Method:** Examined SNI field in each TLS Client Hello within the time window

**Answer:** `finejewels.com.au`, `thietbiagt.com`, `new.americold.com`

**Key technique learned — TLS SNI hunting for C2 domains:**
Even when HTTP traffic is encrypted as TLS/HTTPS, the Server Name Indication (SNI) field in the TLS Client Hello is transmitted in plaintext. Filtering `tls.handshake.type == 1` after a known infection timestamp reveals every domain the malware contacted — without decrypting a single byte.

This is the same technique used in the Day 1 Ursnif investigation to find `fatturapagamentodi.pw` and `asistenzaonline.xyz`.

---

### Q8 — Certificate Authority for First Domain
**Method:** Follow TCP Stream on TLS handshake → examined certificate details
**Verification:** VirusTotal historical WHOIS for `finejewels.com.au`

**Answer:** `GoDaddy`

**Analyst note:** Certificate authority information helps distinguish legitimate sites from attacker-registered domains. Legitimate enterprise sites rarely use GoDaddy for SSL — most use DigiCert, Sectigo, or Let's Encrypt. A GoDaddy cert on a domain flagged by VirusTotal is a supporting indicator.

---

### Q9 — Cobalt Strike C2 Server IP Addresses
**Filter used:** `http.request.method == "GET"`
**Method:** Statistics → Conversations → TCP → sorted by frequency → checked top IPs against VirusTotal Community tab

**Answer:** `185.106.96.158`, `185.125.204.174`

**Key technique learned — Identifying C2 servers via conversation frequency:**
C2 servers receive frequent GET and POST requests from the infected host — this shows up as high conversation counts in the TCP tab. Combining conversation statistics with VirusTotal Community tab confirmation is the standard workflow for C2 identification in PCAP analysis.

Cobalt Strike is a legitimate penetration testing framework that is widely abused by threat actors for post-exploitation C2. Recognizing its network signature is a core SOC analyst skill.

---

### Q10 — Host Header for First Cobalt Strike IP
**Filter used:** `ip.dst == 185.106.96.158 && http`
**Method:** Examined HTTP request → Hypertext Transfer Protocol → `Host:` header

**Answer:** `oscp.verisign.com`

**Analyst note:** Cobalt Strike malleable C2 profiles allow attackers to disguise C2 traffic as requests to legitimate domains (like `verisign.com`). The Host header is spoofed — the actual destination IP (185.106.96.158) has nothing to do with Verisign. This is MITRE T1036 — Masquerading.

---

### Q11 — Domain Name of First Cobalt Strike Server
**Method:** VirusTotal → searched 185.106.96.158 → historical WHOIS (September 2021)

**Answer:** `survmeter.live`

---

### Q12 — Domain Name of Second Cobalt Strike Server
**Method:** VirusTotal → Community tab for 185.125.204.174

**Answer:** `securitybusinpuff.com`

---

### Q13 — Post-Infection Traffic Domain
**Method:** Filtered `http.request.method == "POST"` → identified suspicious recurring POST destination

**Answer:** `maldivehost.net`

**Analyst note:** Post-infection traffic to a domain like `maldivehost.net` (unrelated to the Maldives government — a common attacker tactic of using country-sounding names) is a strong indicator of C2 or data exfiltration activity.

---

### Q14 — First Eleven Characters Sent to Malicious Domain
**Method:** Follow TCP Stream on POST to `maldivehost.net` → read POST body

**Answer:** `zLIisQRWZI`

**Analyst note:** These characters are likely an encoded check-in or session token — malware often sends a short authentication string to the C2 before receiving commands. The specific format can help identify the malware family.

---

### Q15 — Length of First Packet to C2 Server
**Method:** Frame details → Length field

**Answer:** `281`

---

### Q16 — Server Header for Malicious Domain
**Method:** Follow TCP Stream on C2 communication → examine HTTP response headers

**Answer:** `Apache/2.4.49 (cPanel) OpenSSL/1.1.1l mod_bwlimited/1.4`

**Analyst note:** Server headers on C2 infrastructure are often generic or spoofed. Documenting them adds to the attacker's fingerprint.

---

### Q17 — IP Check API — Date and Time of DNS Query
**Filter used:** `dns && frame contains "api"`
**Method:** Filtered DNS traffic → searched for API-related query → excluded known legitimate services (MSN, Microsoft)

**Answer:** `2021-09-24 17:00:04 UTC`

**Analyst note:** This is identical behavior to Trickbot in the Day 2 investigation — querying `api.ipify.org` to confirm the victim's public IP. Seeing this pattern again in a different malware family confirms it is a standard technique across many malware families.

---

### Q18 — IP Check Domain
**Answer:** `api.ipify.org`

**MITRE ATT&CK:** T1016 — System Network Configuration Discovery (same as Trickbot Day 2)

---

### Q19 — First Malspam MAIL FROM Address
**Filter used:** `frame contains "MAIL FROM"`
**Method:** Filtered SMTP traffic for MAIL FROM header

**Answer:** `farshin@mailfa.com`

**Key technique learned — SMTP forensics:**
Using `frame contains "keyword"` is more reliable than protocol-specific filters for finding specific SMTP fields. The lesson: always search for the complete term rather than partial strings.

---

### Q20 — Total SMTP Packets
**Filter used:** `smtp`
**Method:** Applied filter → checked packet count in status bar

**Answer:** `1439`

**Analyst note:** 1,439 SMTP packets indicates a significant malspam campaign originating from or through the infected host — the malware was using the victim's machine to send spam emails, a common Emotet secondary behavior.

---

## Attack Summary

This PCAP captured a complete Emotet-style infection with Cobalt Strike post-exploitation:

```
[Stage 1] Malicious zip delivered → attirenepal.com
          Contains: chart-1530076591.xls (macro-enabled Excel)
      ↓
[Stage 2] XLS macro executes → downloads additional payloads from:
          • finejewels.com.au
          • thietbiagt.com
          • new.americold.com
      ↓
[Stage 3] Cobalt Strike C2 established:
          • survmeter.live (185.106.96.158)
          • securitybusinpuff.com (185.125.204.174)
          Host header spoofed as: oscp.verisign.com
      ↓
[Stage 4] Post-infection C2 → maldivehost.net
          First beacon: "zLIisQRWZI" (281 bytes)
      ↓
[Stage 5] IP reconnaissance → api.ipify.org (17:00:04 UTC)
      ↓
[Stage 6] Malspam campaign → 1,439 SMTP packets
          First sender: farshin@mailfa.com
```


The victim system downloaded a malicious ZIP file from a compromised domain.  
The archive contained a malicious Excel file, likely used to initiate infection.

Post-infection activity included:
- Communication with multiple malicious domains
- Connection to Cobalt Strike C2 servers
- Data exfiltration via HTTP POST requests
- External IP verification using API

---

## Victim Information
- Victim IP: 10.11.9.102
- MAC Address: 00:08:02:1c:47:ae

---

## Initial Infection

- First HTTP connection: **2021-09-24 16:44:38**
- Malicious domain: `attirenepal[.]com`
- Downloaded file: `documents.zip`
- File inside archive: `chart-1530076591.xls`

---

## Malicious Infrastructure

### Domains:
- attirenepal[.]com
- finejewels[.]com[.]au
- thietbiagt[.]com
- new[.]americold[.]com
- maldivehost[.]net
- survmeter[.]live
- securitybusinpuff[.]com

---

### Cobalt Strike C2 Servers:
- 185[.]106[.]96[.]158
- 185[.]125[.]204[.]174

Host header observed:
- oscp[.]verisign[.]com

---

## Post-Infection Activity

- Data exfiltration via HTTP POST requests
- Domain used: `maldivehost[.]net`
- Sample exfiltrated data: `zLIisQRWZI`
- Packet length: 281 bytes

---

## Additional Findings

- Web server: LiteSpeed
- Server version: PHP/7.2.34
- SSL Certificate Authority: GoDaddy

---

## DNS Activity

- IP check domain: `api.ipify[.]org`
- Timestamp: **2021-09-24 17:00:04**

---

## Malspam Activity

- First MAIL FROM address:
  - farshin@mailfa[.]com
- Total SMTP packets: 1439

---

## MITRE ATT&CK Mapping

| ID | Technique | Evidence |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Malicious zip with XLS macro |
| T1059.005 | Command and Scripting Interpreter: VBA | Excel macro delivery |
| T1105 | Ingress Tool Transfer | Zip + XLS download from attirenepal.com |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP C2 to Cobalt Strike servers |
| T1573.001 | Encrypted Channel | TLS to finejewels.com.au, thietbiagt.com |
| T1036 | Masquerading | Host header spoofed as oscp.verisign.com |
| T1016 | System Network Configuration Discovery | GET api.ipify.org |
| T1583 | Acquire Infrastructure | Multiple attacker-controlled domains |
| T1071.003 | Application Layer Protocol: Mail Protocols | Malspam via SMTP — 1,439 packets |

---

## Key Techniques Learned Today

| Technique | Filter / Method | When to Use |
|---|---|---|
| TLS SNI hunting | `tls.handshake.type == 1` | Finding C2 domains in encrypted traffic |
| Hex inspection | View → Packet Bytes | Finding embedded filenames in downloads |
| C2 identification | Statistics → Conversations + VirusTotal | Finding high-frequency external connections |
| SMTP forensics | `frame contains "MAIL FROM"` | Finding email sender in spam campaigns |
| Time-bounded filtering | Edit → Find Packet + time range | Narrowing TLS handshakes to infection window |
| TCP stream follow | Right-click → Follow → TCP Stream | Reading full C2 conversations |

---

## New Wireshark Filters Added to Toolkit

```wireshark
tls.handshake.type == 1              TLS Client Hello — reveals SNI (C2 domains)
frame contains "MAIL FROM"           SMTP sender identification
smtp                                 All SMTP traffic
http.request.method == "POST"        Data exfiltration and C2 check-ins
ip.dst == x.x.x.x && http           HTTP traffic to specific destination
```

---

## IOC Table

| Type | Value | Role |
|---|---|---|
| Domain | attirenepal.com | Initial payload delivery |
| File | documents.zip | Malicious zip |
| File | chart-1530076591.xls | Macro-enabled Excel payload |
| Domain | finejewels.com.au | Secondary payload |
| Domain | thietbiagt.com | Secondary payload |
| Domain | new.americold.com | Secondary payload |
| IP | 185.106.96.158 | Cobalt Strike C2 |
| IP | 185.125.204.174 | Cobalt Strike C2 |
| Domain | survmeter.live | Cobalt Strike C2 |
| Domain | securitybusinpuff.com | Cobalt Strike C2 |
| Domain | maldivehost.net | Post-infection C2 |
| Domain | api.ipify.org | IP check (abused) |
| Email | farshin@mailfa.com | Malspam sender |

---

## Key Learnings

- Identified malware infection via HTTP download
- Detected C2 communication using TLS and HTTP
- Used VirusTotal to validate malicious infrastructure
- Analyzed SMTP traffic for malspam activity

---

## SOC Relevance

This investigation demonstrates:
- Network traffic analysis using Wireshark
- Detection of malware delivery and execution
- Identification of C2 infrastructure
- Extraction of IOCs for threat detection

---

## References
- TryHackMe: Carnage Room
- Cobalt Strike on MITRE ATT&CK: https://attack.mitre.org/software/S0154/
- Emotet on MITRE ATT&CK: https://attack.mitre.org/software/S0367/

---
*Himanshu Kumar Modi | Associate at PwC India | SOC Analyst in Training*
*[LinkedIn](https://www.linkedin.com/in/himanshu-kumar-modi-063b88239) | [Cybersecurity Portfolio](https://github.com/himanshumodi3108/cybersec-portfolio)*
