# Network Forensics Investigation Report
## Case: Trickbot Infostealer — Credential Exfiltration
**Date of Analysis:** 2025-03-22
**Analyst:** Himanshu Kumar Modi
**Exercise Source:** malware-traffic-analysis.net — 2020-11-09
**PCAP File:** 2020-11-09-Trickbot-gtag-tar2-infection-traffic.pcap
**Certifications:** Google Cybersecurity Certificate | ISC2 CC

---

## 1. Executive Summary

A Windows host (`DESKTOP-CANDLES`, 10.11.9.102) was compromised by **Trickbot**, a modular banking trojan and infostealer. The malware established encrypted C2 channels to multiple external servers and exfiltrated sensitive data including **plaintext browser-saved passwords** and **personally identifiable information (PII)** via HTTP POST to 51.81.112.135. The victim's Google, Facebook, and Yahoo credentials were transmitted in cleartext inside multipart form-data POST requests. This constitutes a full credential compromise event requiring immediate account resets across all identified services.

**Severity:** Critical
**Infection Type:** Trickbot Infostealer / Banking Trojan
**Total Packets Analyzed:** 2,502
**Data Exfiltrated:** Browser credentials (Google, Facebook, Yahoo), billing info, form data

---

## 2. Victim Details

| Field | Value |
|---|---|
| Hostname | DESKTOP-CANDLES |
| IP Address | 10.11.9.102 |
| MAC Address | 00:08:02:1c:47:ae |
| OS | Windows 10 build 19042 (confirmed via User-Agent and hostname) |
| Domain ID | W10019042.1C550D7482EBE49086FC1A7D2100C9E5 |
| Total Packets | 2,502 (highest conversation count — confirmed victim) |

> **Analyst Note:** The Trickbot bot ID embedded in the POST URI (`DESKTOP-CANDLES_W10019042.1C550D7482EBE49086FC1A7D2100C9E5`) uniquely identifies this infected machine to the attacker's C2 infrastructure. This ID is generated from the hostname and a hardware fingerprint — it persists across reboots.

---

## 3. Infection Chain (Packet-Level Timeline)

```
[Stage 1]  Pkt #21   · 21:30:01 UTC · rel: 1.144s
           GET / HTTP/1.1 → 184.73.247.141 (icanhazip.com)
           WHY SUSPICIOUS: no user action triggers an IP-check service;
           only malware does this automatically post-infection
           Pkt #23 · 21:30:01 UTC → 200 OK, public IP returned
      ↓
[Stage 2]  Pre-capture
           HTTPS C2 check-in → 66.85.183.5:443 (462 packets)
           WHY SUSPICIOUS: sustained HTTPS to a bare IP — no domain,
           no SNI hostname — legitimate cloud services use domain names
      ↓
[Stage 3]  Pre-capture
           HTTPS C2 → 167.86.123.83:447 (1,484 packets — highest volume)
           WHY SUSPICIOUS: port 447 is not standard HTTPS (443);
           evades firewalls that only inspect port 443 traffic
      ↓
[Stage 4]  Pkt #1592 · 21:33:44 UTC · rel: 224.049s
           POST /tar2/DESKTOP-CANDLES_W10019042.../81/ → 51.81.112.135
           Payload: 627 bytes — Chrome saved passwords (Google x3, Facebook x1)
           WHY SUSPICIOUS: HTTP on port 443 — not TLS; attacker uses
           port 443 to blend with HTTPS traffic while POST body stays
           unencrypted for easy server-side parsing
           Pkt #1599 · 21:33:44 UTC → 200 OK, data confirmed received
      ↓
[Stage 5]  Pkt #1727 · 21:34:10 UTC · rel: 250.533s
           POST /tar2/DESKTOP-CANDLES_W10019042.../90 → 156.96.128.237
           Payload: 120 bytes — additional data module
           Pkt #1732 · 21:34:10 UTC → 200 OK
      ↓
[Stage 6]  Pkt #1753 · 21:34:15 UTC · rel: 255.788s
           POST /tar2/DESKTOP-CANDLES_W10019042.../83/ → 51.81.112.135
           Payload: 612 bytes — form data, billing info, Yahoo PII
           Pkt #1760 · 21:34:16 UTC → 200 OK
      ↓
[Stage 7]  Pkt #2109 · 21:34:47 UTC · rel: 287.835s
           POST /tar2/.../81/ → 51.81.112.135 (346 bytes — repeat password send)
           Pkt #2112 · 21:34:48 UTC → 200 OK
      ↓
[Stage 8]  Pkt #2138 · 21:35:20 UTC · rel: 320.119s
           POST /tar2/.../83/ → 51.81.112.135 (637 bytes — repeat form data)
           Pkt #2141 · 21:35:20 UTC → 200 OK — final confirmation

![Trickbot Infection Chain](<Day 2_Trickbot_infection_chain.png>)
```

> **Exfiltration window:** 96.3 seconds — from Pkt #1592 (21:33:44) to Pkt #2141 (21:35:20 UTC)
> **Total data sent:** 2,342 bytes across 5 POST requests
> **Server confirmations:** 5 × HTTP 200 OK — every payload confirmed received by attacker
> **Critical insight:** The entire credential theft completed in under 2 minutes. By the time a SOC analyst manually triages an alert, the data is already gone. Automated real-time detection rules are the only viable defense against this exfiltration speed.

---

## 4. Protocol Analysis — Data Volume & Suspicion Reasoning

| IP | Packets | Port | Protocol | Data Volume | Why Suspicious |
|---|---|---|---|---|---|
| 10.11.9.102 | 2,502 | — | — | All traffic | Victim — highest packet count confirms this host |
| 167.86.123.83 | 1,484 | 447 | HTTPS | Highest volume | Non-standard port 447 — evades port-443-only inspection |
| 66.85.183.5 | 462 | 443 | HTTPS | Medium volume | Bare IP, no domain — legitimate services use domain names |
| 51.81.112.135 | — | 443 | HTTP (plain) | 2,222 bytes across 4 POSTs (pkts 1592,1753,2109,2138) | Port 443 but NOT TLS — attacker mimics HTTPS port, sends unencrypted POST |
| 156.96.128.237 | — | 443 | HTTP | Module 90 data | Same exfil pattern — secondary collection endpoint |
| icanhazip.com | — | 80 | HTTP GET | Minimal | Legitimate site abused — no user manually browses an IP-check service |

> **Data Volume Insight (packet-precise):** 167.86.123.83:447 had the highest packet count (1,484) — primary C2 channel. The exfiltration server 51.81.112.135:443 received 2,222 bytes across 4 POST requests. 156.96.128.237 received 120 bytes (module 90). Total confirmed exfiltrated: **2,342 bytes across 5 POST requests, all acknowledged with HTTP 200 OK**. The complete exfiltration window was **96.3 seconds** — Pkt #1592 at 21:33:44 to Pkt #2141 at 21:35:20 UTC.

> **Why HTTP on port 443?** Deliberate attacker technique. Most firewall rules filter by port number — port 443 is assumed to be HTTPS and therefore "safe." By sending plain HTTP POST on port 443, Trickbot exploits this assumption. The stolen credentials travel unencrypted while the port number causes automated systems to treat the traffic as normal web activity. SSL/TLS inspection at the proxy layer would have caught this immediately — making TLS inspection a critical defensive control against this attack pattern.

---

## 5. Exfiltrated Data (Critical)

### 5a. Chrome Saved Passwords — POST /tar2/.../81/

The following credentials were captured in plaintext inside the HTTP POST body:

| Service | Username | Password |
|---|---|---|
| accounts.google.com | xavier.f.candles1@gmail.com | P@ssw0rd-12 |
| accounts.google.com | xavier.f.candles2@gmail.com | P@ssw0rd$ |
| accounts.google.com | xavier.francis.candles@gmail.com | C4ndl3z-f0r-Lyfe!!?!?!? |
| facebook.com | xavier.francis.candles@gmail.com | P@ssw0rd123456789$ |

**Source field:** `chrome passwords` — confirms Trickbot's browser credential harvesting module.

### 5b. Form Data + PII — POST /tar2/.../83/

| Field | Value |
|---|---|
| Zipcode | 91839 |
| Verification text | 6278942059 |
| User ID | candlez38 |
| Email | xavier.f.candles.1982@yahoo.com |

**Analyst Note:** The `billinfo` and `cardinfo` fields in the POST body indicate Trickbot attempted to harvest payment card information. The `cardinfo` field returned malformed JSON (`{]}`), suggesting the credit card module found no stored card data on this machine. The billing address fields were empty — victim likely had no saved payment details in the browser.

### 5c. POST URI Structure Analysis

```
POST /tar2/DESKTOP-CANDLES_W10019042.1C550D7482EBE49086FC1A7D2100C9E5/81/
                │                    │                                   │
                │                    │                                   └── Module ID
                │                    │                                       81 = passwords
                │                    │                                       83 = form data
                │                    │                                       90 = additional
                │                    └── Hardware fingerprint (unique bot ID)
                └── Base path (Trickbot C2 routing)
```

---

## 6. Indicators of Compromise (IOCs)

### Network IOCs

| Type | Value | Confidence | Description |
|---|---|---|---|
| IP | 66.85.183.5 | High | Primary C2 — HTTPS:443 — 462 packets |
| IP | 167.86.123.83 | High | Secondary C2 — HTTPS:447 — 1484 packets — non-standard port |
| IP | 51.81.112.135 | High | Exfiltration server — HTTP POST /tar2/ — passwords + PII |
| IP | 156.96.128.237 | High | Additional exfiltration endpoint — POST /tar2/.../90/ |
| Domain | icanhazip.com | Medium | Public IP check — Trickbot recon (legitimate site abused) |
| URI pattern | /tar2/[HOSTNAME]_[ID]/[module]/ | High | Trickbot exfiltration URI — unique bot routing |
| Port | 447 outbound | High | Non-standard HTTPS port — Trickbot C2 evasion |

### Host IOCs

| Type | Value | Confidence | Description |
|---|---|---|---|
| Hostname | DESKTOP-CANDLES | High | Compromised machine |
| Bot ID | DESKTOP-CANDLES_W10019042.1C550D7482EBE49086FC1A7D2100C9E5 | High | Trickbot unique machine identifier |
| User-Agent | Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0...) | High | Trickbot spoofed User-Agent — fake IE7 |

### Compromised Accounts

| Service | Account |
|---|---|
| Google | xavier.f.candles1@gmail.com |
| Google | xavier.f.candles2@gmail.com |
| Google | xavier.francis.candles@gmail.com |
| Facebook | xavier.francis.candles@gmail.com |
| Yahoo | xavier.f.candles.1982@yahoo.com |

---

## 7. MITRE ATT&CK Mapping

| Technique ID | Name | Evidence |
|---|---|---|
| T1566 | Phishing | Inferred delivery vector — consistent with Trickbot campaigns |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP POST exfiltration to 51.81.112.135 |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | HTTPS C2 to 66.85.183.5 and 167.86.123.83 |
| T1041 | Exfiltration Over C2 Channel | Credentials and PII sent via POST /tar2/ |
| T1555.003 | Credentials from Web Browsers | Chrome saved passwords harvested and exfiltrated |
| T1082 | System Information Discovery | Bot ID includes OS build (W10019042) and hardware fingerprint |
| T1016 | System Network Configuration Discovery | GET icanhazip.com — public IP lookup |
| T1571 | Non-Standard Port | C2 on port 447 — evades port-443-only firewall rules |
| T1036 | Masquerading | User-Agent spoofs IE7 on Windows 10 — impossible combination |

---

## 8. Detection Rules (Splunk SPL)

### Detection 1 — Trickbot URI pattern in HTTP traffic (T1041)
```spl
index=network http.request.method=POST
  http.uri="/tar2/*"
| rex field=http.uri "/tar2/(?<bot_id>[^/]+)/(?<module_id>\d+)/"
| stats count by src_ip, dest_ip, bot_id, module_id
| table src_ip, dest_ip, bot_id, module_id, count
```
**Logic:** Matches the Trickbot-specific `/tar2/[botID]/[moduleID]/` URI pattern. Any match is high-confidence Trickbot activity. No false positives expected.

---

### Detection 2 — Outbound HTTPS on non-standard port (T1571)
```spl
index=network dest_port!=443 dest_port!=80
  (dest_port=447 OR dest_port=449 OR dest_port=8082)
| stats count by src_ip, dest_ip, dest_port
| where count > 10
| sort -count
```
**Logic:** Catches Trickbot's port 447 C2 evasion technique. Legitimate HTTPS is almost always port 443. Sustained outbound traffic to port 447 or similar non-standard ports from an internal host is a strong Trickbot indicator.

---

### Detection 3 — Impossible User-Agent combination (T1036)
```spl
index=network http.user_agent="*MSIE 7.0*" http.user_agent="*Windows NT 10.0*"
| stats count by src_ip, dest_ip, http.user_agent
| sort -count
```
**Logic:** IE7 (MSIE 7.0) was released in 2006 and cannot run on Windows 10. Any User-Agent claiming to be IE7 on Windows 10 is definitively malware — no legitimate browser produces this string. Zero false positives.

---

### Detection 4 — Public IP lookup by internal host (T1016)
```spl
index=network http.request.method=GET
  (http.host="icanhazip.com" OR http.host="checkip.amazonaws.com"
   OR http.host="api.ipify.org" OR http.host="ifconfig.me")
| stats count by src_ip, http.host
| where count > 2
```
**Logic:** Malware routinely checks its public IP to confirm connectivity and geolocation. Repeated GET requests to IP-check services from a single internal host — especially combined with other suspicious traffic — is a lateral indicator of compromise.

---

### Detection 5 — Large credential POST to external IP (T1555.003 + T1041)
```spl
index=network http.request.method=POST
| eval dest_internal=if(match(dest_ip,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01]))"),1,0)
| where dest_internal=0
| eval body_size=coalesce(http.content_length, 0)
| where body_size > 200
| stats count, max(body_size) as max_body by src_ip, dest_ip, http.uri
| sort -max_body
```
**Logic:** Flags large HTTP POST bodies sent to external IPs. The credential exfiltration POST in today's PCAP was 573 bytes — above a 200-byte threshold that filters out trivial requests. Combine with URI pattern matching for higher confidence.

---

## 9. Comparison to Day 1 — Ursnif vs Trickbot

| Dimension | Day 1 — Ursnif | Day 2 — Trickbot |
|---|---|---|
| Infection vector | Excel macro | Not captured (likely phishing) |
| Payload delivery | HTTP GET .avi files (disguised DLLs) | Not observed — already installed |
| C2 protocol | TLS beaconing on port 443 | HTTPS on ports 443 AND 447 (non-standard) |
| Evasion technique | .avi extension for DLL files | Fake IE7 User-Agent + non-standard port 447 |
| Data theft | Not observed | Plaintext credentials + PII via HTTP POST |
| Bot identification | Domain-based C2 SNI | Unique bot ID embedded in POST URI |
| Recon behavior | None observed | Public IP check via icanhazip.com |
| Severity | High | Critical — active credential theft confirmed |

> **Key insight:** Trickbot is significantly more dangerous than Ursnif in this capture because the exfiltration was caught in plaintext — the POST to port 443 was HTTP, not HTTPS, meaning the stolen credentials transmitted unencrypted. This is a deliberate attacker choice: using port 443 to blend with HTTPS traffic while keeping the payload unencrypted for easier C2 processing.

---

## 10. Immediate Response Recommendations

| Priority | Action |
|---|---|
| P0 — Immediate | Force password reset on ALL 5 compromised accounts (Google x3, Facebook, Yahoo) |
| P0 — Immediate | Enable MFA on all compromised accounts immediately |
| P1 — Immediate | Isolate DESKTOP-CANDLES (10.11.9.102) from network |
| P1 — Immediate | Block 4 attacker IPs at perimeter firewall |
| P1 — Immediate | Block outbound port 447 at firewall — Trickbot C2 evasion port |
| P2 — Same day | Search all proxy logs for GET requests to icanhazip.com from other internal hosts |
| P2 — Same day | Hunt for /tar2/ URI pattern in all web proxy logs for past 30 days |
| P2 — Same day | Check if DESKTOP-CANDLES has domain credentials — Trickbot spreads laterally |
| P3 — This week | Scan all endpoints for the Trickbot bot ID pattern in network logs |
| P3 — This week | Review browser password storage policy — enforce no-save policy via GPO |

---

## 11. Tools Used

| Tool | Purpose |
|---|---|
| Wireshark | Primary packet analysis |
| Statistics → Conversations | Identified top talkers (167.86.123.83 = 1484 packets) |
| Follow → HTTP Stream | Captured plaintext credentials in POST body |
| http.user_agent filter | Identified spoofed IE7 User-Agent |
| http.request.method == POST | Located exfiltration traffic |
| VirusTotal | IP reputation confirmation |
| MITRE ATT&CK Navigator | TTP mapping |

---

## 12. References
- Exercise: https://malware-traffic-analysis.net/2020/11/09/index.html
- MITRE ATT&CK Trickbot: https://attack.mitre.org/software/S0266/
- Trickbot analysis: https://malpedia.caad.fkie.fraunhofer.de/details/win.trickbot

---
*Report generated as part of SOC Analyst / DFIR portfolio development.*
*Analyst: Himanshu Kumar Modi | [LinkedIn Profile](https://www.linkedin.com/in/himanshu-kumar-modi-063b88239/)*
