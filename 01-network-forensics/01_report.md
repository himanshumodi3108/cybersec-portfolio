# Network Forensics Investigation Report
## Case: Ursnif Malware Infection via Excel Macro
**Date of Analysis:** 2025-03-20
**Analyst:** Himanshu Kumar Modi
**Exercise Source:** malware-traffic-analysis.net — 2020-02-24
**PCAP File:** 2020-02-24-Ursnif-infection-from-Italian-XLS-macro.pcap
**Certifications:** Google Cybersecurity Certificate | ISC2 CC

---

## 1. Executive Summary

A Windows host (10.2.24.101) was compromised via a malicious Excel document containing an embedded macro. The macro triggered a multi-stage infection chain: it initiated TLS connections to retrieve an encrypted payload, downloaded disguised DLL files (masquerading as `.avi` media files) over HTTP, and retrieved additional 32-bit and 64-bit binaries (`grabb32.rar`, `grabb64.rar`). Post-infection, the host established persistent C2 beaconing to `asistenzaonline.xyz` (68.168.123.78) via TLS at approximately 5–10 minute intervals. The malware family is consistent with **Ursnif (Gozi)** banking trojan behavior.

**Severity:** Critical
**Infection Type:** Banking Trojan — Multi-stage
**Total Packets Analyzed:** 2,180

---

## 2. Victim Details

| Field | Value |
|---|---|
| IP Address | 10.2.24.101 |
| MAC Address | 00:08:02:1c:47:ae |
| Suspected OS | Windows (based on TLS fingerprint and HTTP User-Agent) |
| Role | Compromised endpoint |

---

## 3. Infection Chain (Timeline)

```
[Stage 1] Phishing Email → Malicious Excel (.xls) delivered to victim
      ↓
[Stage 2] Macro Execution → Packet 10: TLS Client Hello to fatturapagamentodi.pw (217.138.205.170)
      ↓
[Stage 3] Payload Download → Packets 218–1116: HTTP GET requests to 46.102.153.16
          Disguised payloads: multiple .avi files (chunked Ursnif DLL segments)
      ↓
[Stage 4] Secondary Payload → Packets 1299, 1563: HTTP GET /grabb32.rar + /grabb64.rar
          from 37.10.71.149 (32-bit and 64-bit binaries)
      ↓
[Stage 5] C2 Beaconing → Packets 1215–2167: Repeated TLS handshakes to
          asistenzaonline.xyz (68.168.123.78) every ~5–10 minutes
      ↓
[Stage 6] Persistence → Suspected registry autostart (DLL drop pattern consistent
          with Ursnif HKCU\Software registry injection)
```
![Infection Chain](<Day 1_Infection Chain.jpeg>)
---

## 4. Protocol Analysis

| Protocol | % of Traffic | Significance |
|---|---|---|
| TCP | 97.9% | Dominant — all malware traffic is TCP-based |
| TLS | 8.2% | C2 beaconing + initial payload retrieval (encrypted) |
| HTTP | Present | Plaintext payload download (.avi files, .rar files) |

**Key observation:** Attacker deliberately mixed HTTP (payload download) with TLS (C2) to blend into normal browsing traffic. The use of `.avi` file extensions is a classic Ursnif evasion technique to bypass content-type based filtering.

---

## 5. Indicators of Compromise (IOCs)

### 5a. Network IOCs

| Type | Value | Role | Notes |
|---|---|---|---|
| IP | 217.138.205.170 | Initial C2 / payload retrieval | TLS SNI: fatturapagamentodi.pw — Packet 10 |
| IP | 46.102.153.16 | Payload server | HTTP GETs for .avi files — Packets 218–1116 (10 packets) |
| IP | 37.10.71.149 | Secondary payload server | HTTP GET /grabb32.rar + /grabb64.rar |
| IP | 68.168.123.78 | Primary C2 server | TLS beaconing — Packets 1215, 1230, 1247, 1271, 1284, 1933–2167 |
| Domain | fatturapagamentodi.pw | Stage 2 C2 | First contact post-macro execution |
| Domain | asistenzaonline.xyz | Primary C2 | Persistent beaconing, ~5–10 min intervals |
| Domain | pizdelko.xyz | C2 / payload | Packet 1159 — TLS Client Hello |
| URL | http://46.102.153.16/*.avi | Payload delivery | Chunked DLL download disguised as media |
| URL | http://37.10.71.149/grabb32.rar | Secondary payload | 32-bit binary |
| URL | http://37.10.71.149/grabb64.rar | Secondary payload | 64-bit binary |

### 5b. Host IOCs

| Type | Value | Notes |
|---|---|---|
| File | grabb32.rar | 32-bit Ursnif DLL — retrieved post initial compromise |
| File | grabb64.rar | 64-bit Ursnif DLL — retrieved post initial compromise |
| File pattern | *.avi (non-media) | Ursnif DLL segments disguised as media files |
| Registry (suspected) | HKCU\Software\[random] | Ursnif persistence mechanism — DLL injection |

---

## 6. MITRE ATT&CK Mapping

| Technique ID | Name | Observed Evidence |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Excel macro delivery vector (inferred from infection pattern) |
| T1059.005 | Command and Scripting Interpreter: VBA | Excel macro triggered initial C2 connection at Packet 10 |
| T1105 | Ingress Tool Transfer | HTTP GET of .avi files (Packets 218–1116) and .rar files (Packets 1299, 1563) |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based payload download from 46.102.153.16 |
| T1071.003 | Application Layer Protocol: Mail Protocols | TLS-encrypted C2 to asistenzaonline.xyz and fatturapagamentodi.pw |
| T1547.001 | Boot/Logon Autostart: Registry Run Keys | Suspected — consistent with Ursnif DLL persistence pattern |
| T1027 | Obfuscated Files or Information | .avi extension masking DLL payloads; TLS encryption of C2 |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | TLS used for C2 communication to evade inspection |

---

## 7. Detection Rules (Splunk SPL)

### Detection 1 — TLS connection to suspicious SNI (T1071.003)
```spl
index=network ssl.handshake.type=1
| stats count by src_ip, ssl.handshake.extensions_server_name
| where NOT ssl.handshake.extensions_server_name LIKE "%.google.com"
  AND NOT ssl.handshake.extensions_server_name LIKE "%.microsoft.com"
  AND NOT ssl.handshake.extensions_server_name LIKE "%.cloudflare.com"
| sort -count
```
**Logic:** Surfaces TLS Client Hello packets to domains not matching known-good providers. Analyst reviews flagged SNIs against threat intel.

---

### Detection 2 — C2 beaconing via regular TLS intervals (T1071.003 + T1573)
```spl
index=network ssl.handshake.type=1
| bucket _time span=10m
| stats count by src_ip, dest_ip, _time
| where count >= 2
| streamstats window=6 current=t stdev(count) as regularity by src_ip, dest_ip
| where regularity < 1.5
| table src_ip, dest_ip, count, regularity
```
**Logic:** Low standard deviation in connection count over time = machine-like regularity = beaconing. Threshold of 1.5 tunable based on environment.

---

### Detection 3 — HTTP download of non-media file with media extension (T1105 + T1027)
```spl
index=network http.request.method=GET
| rex field=uri "(?<ext>\.[a-z0-9]{2,4})$"
| where ext IN (".avi", ".mp4", ".mp3", ".jpg", ".png")
| eval dest_is_cdn=if(match(dest_ip,"^(151\.101|104\.16|172\.67)"),1,0)
| where dest_is_cdn=0
| stats count by src_ip, dest_ip, uri, ext
| where count > 3
```
**Logic:** Flags repeated GET requests for media-extension files from non-CDN IPs — a strong Ursnif payload delivery indicator.

---

### Detection 4 — Multiple payload downloads from same external IP (T1105)
```spl
index=network http.request.method=GET
| stats dc(uri) as unique_files, count as total_requests
  by src_ip, dest_ip
| where unique_files > 3 AND dest_ip!="0.0.0.0"
| eval internal=if(match(dest_ip,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01]))"),1,0)
| where internal=0
| sort -total_requests
```
**Logic:** An infected host downloading many distinct files from a single external IP (906 packets to 46.102.153.16) is a high-confidence payload staging indicator.

---

### Detection 5 — Executable download disguised as archive (T1027)
```spl
index=network http.request.method=GET
  (uri="*.rar" OR uri="*.zip" OR uri="*.cab")
| where NOT dest_ip LIKE "192.168.%" AND NOT dest_ip LIKE "10.%"
| stats count by src_ip, dest_ip, uri
| eval suspicious_name=if(match(uri,"(grabb|load|drop|payload|stage)"),1,0)
| where suspicious_name=1 OR count > 2
```
**Logic:** Catches downloads of archives with suspicious naming conventions like `grabb32.rar` / `grabb64.rar` — direct match for this Ursnif sample.

---

## 8. Analyst Notes & Observations

- The use of `.avi` extensions for DLL payloads is a **known Ursnif evasion technique** — it bypasses content-type based firewalls and proxy filters that only block `.exe` and `.dll` extensions.
- **pizdelko.xyz** (Packet 1159) appeared only once — likely a fallback C2 or a redirect point in the infection chain. Worth monitoring for reuse in future campaigns.
- The **906 packets to 46.102.153.16** (chunked downloads) suggests the payload was split into segments and reconstructed in memory — a fileless-adjacent technique designed to evade endpoint AV scanning of dropped files.
- The Wireshark filter `(http.request or ssl.handshake.type==1) and !(ssdp)` used during analysis is an excellent general-purpose malware hunting filter worth keeping in your toolkit.

---

## 9. Immediate Response Recommendations

| Priority | Action |
|---|---|
| P1 — Immediate | Isolate 10.2.24.101 from network |
| P1 — Immediate | Block all 4 attacker IPs at perimeter firewall |
| P1 — Immediate | Block domains: fatturapagamentodi.pw, asistenzaonline.xyz, pizdelko.xyz at DNS |
| P2 — Same day | Search all endpoint logs for connections to these IPs/domains — check for lateral spread |
| P2 — Same day | Submit grabb32.rar + grabb64.rar hashes to VirusTotal + internal threat intel platform |
| P3 — This week | Hunt for .avi GET requests across all proxy/firewall logs for past 30 days |
| P3 — This week | Review Excel macro execution events (Event ID 4688) across all endpoints |

---

## 10. Tools Used

| Tool | Purpose |
|---|---|
| Wireshark 4.x | Primary packet analysis |
| Statistics → Conversations | Identified top talkers and victim IP |
| Statistics → Protocol Hierarchy | Confirmed TCP/TLS dominance |
| TLS filter (ssl.handshake.type==1) | Isolated C2 SNI discovery |
| HTTP filter + Export Objects | Payload identification |
| VirusTotal | Domain and hash reputation lookup |
| MITRE ATT&CK Navigator | TTP mapping |

---

## 11. Attack Narrative

The victim machine was likely compromised through a malicious Excel document delivered via phishing email — a delivery method consistent with Ursnif campaigns throughout 2020. Upon opening, the embedded VBA macro executed silently without user awareness, establishing the first external connection before the victim saw any visible change.

The attacker used a multi-stage architecture deliberately — each stage uses separate infrastructure, making it harder to take down the entire campaign by blocking a single server. The `.avi` file extension for DLL payloads was chosen specifically to bypass content-type filtering that blocks `.exe` and `.dll` downloads. Once assembled, the malware established a persistent C2 channel beaconing every 5–10 minutes — designed to look like normal background HTTPS traffic to any analyst not measuring connection regularity.

This is a textbook Ursnif campaign: sophisticated delivery, layered infrastructure, deliberate evasion, and persistent access as the end goal.

---

## 12. Impact Assessment

| Impact Category | Detail |
|---|---|
| Confidentiality | High — attacker has persistent encrypted channel to victim machine |
| Integrity | High — DLL injection likely modified running processes |
| Availability | Medium — system operational but compromised |
| Financial risk | High — Ursnif is a banking trojan targeting financial credentials |
| Lateral movement risk | High — compromised host can be used to pivot to internal network |

---

## 13. Recommended Actions

| Priority | Action |
|---|---|
| P0 | Isolate 10.2.24.101 from network immediately |
| P0 | Block all 4 attacker IPs and 3 domains at perimeter |
| P1 | Scan all endpoints for .avi GET requests in proxy logs (past 30 days) |
| P1 | Check for registry persistence keys on affected host |
| P2 | Review all Excel macro execution events (Event ID 4688) across environment |
| P2 | Re-image affected machine after forensic acquisition |
| P3 | Deploy detection rules 001–005 to SIEM for ongoing monitoring |

---

## 14. References

- Exercise: https://malware-traffic-analysis.net/2020/02/24/index.html
- MITRE ATT&CK: https://attack.mitre.org
- Ursnif/Gozi analysis: https://malpedia.caad.fkie.fraunhofer.de/details/win.gozi
- VirusTotal: https://virustotal.com

---

*Report generated as part of SOC Analyst / DFIR portfolio development.*
*Analyst: Himanshu Kumar Modi | [LinkedIn Profile](https://www.linkedin.com/in/himanshu-kumar-modi-063b88239/)*
