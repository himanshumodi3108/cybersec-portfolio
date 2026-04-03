# Incident Report — BazarLoader via TA551 (Shathak) Campaign
**Date of Analysis:** 2026-03-25
**Analyst:** Himanshu Kumar Modi
**Exercise Source:** malware-traffic-analysis.net — 2021-09-10
**Certifications:** Google Cybersecurity Certificate | ISC2 CC

---

## Executive Summary

On 2021-09-10 at approximately 23:17 UTC, a Windows host belonging to user **Hobart Gunnarsson** on the `angrypoutine.com` domain was infected with **BazarLoader** through the **TA551 (Shathak)** threat actor campaign. The malware was delivered via a password-protected zip archive containing a malicious Word document. Execution of the document triggered an HTTP GET request to retrieve a 64-bit BazarLoader DLL from `simpsonsavingss.com`. Post-infection C2 communication was established over HTTPS to two external servers. No follow-on payloads (Cobalt Strike or DarkVNC) were observed in this capture.

**Severity:** High
**Infection Type:** BazarLoader DLL — TA551 (Shathak) campaign
**Threat Actor:** TA551 / Shathak

---

## 1. Network Environment

| Field | Value |
|---|---|
| LAN Segment | 10.9.10.0/24 |
| Domain | angrypoutine.com |
| Domain Controller | 10.9.10.9 — ANGRYPOUTINE-DC |
| Gateway | 10.9.10.1 |
| Broadcast | 10.9.10.255 |

---

## 2. Victim Details

| Field | Value |
|---|---|
| IP Address | 10.9.10.102 |
| MAC Address | 00:4f:49:b1:e8:c3 |
| Hostname | DESKTOP-KKITB6Q |
| Windows User | hobart.gunnarsson |
| Domain | angrypoutine.com |
| Infection Time | 2021-09-10 ~23:17 UTC |

---

## 3. Infection Chain

```
[Stage 1] TA551 phishing email delivered to hobart.gunnarsson
          Contains: password-protected zip archive
          Inside zip: malicious Word document (.doc)
      ↓
[Stage 2] User opens Word document → macro executes
          HTTP GET → simpsonsavingss.com
          URL: /bmdff/BhoHsCtZ/MLdmpfjaX/5uFG3Dz7yt/date1?BNLv65=pAAS
          Response: 64-bit BazarLoader DLL (284,816 bytes)
      ↓
[Stage 3] BazarLoader DLL executes on victim host
          (DLL requires explicit execution — not auto-run)
      ↓
[Stage 4] C2 beaconing established over HTTPS:
          • 167.172.37.9 port 443
          • 94.158.245.52 port 443
      ↓
[Stage 5] No follow-on payload observed
          (No Cobalt Strike or DarkVNC in this capture)
```

---

## 4. Indicators of Compromise (IOCs)

### Network IOCs

| Type | Value | Role |
|---|---|---|
| IP | 194.62.42.206 | BazarLoader DLL delivery server |
| Domain | simpsonsavingss.com | Payload hosting — TA551 infrastructure |
| URL | http://simpsonsavingss.com/bmdff/BhoHsCtZ/MLdmpfjaX/5uFG3Dz7yt/date1?BNLv65=pAAS | Full DLL download URL |
| IP | 167.172.37.9 | BazarLoader C2 — HTTPS port 443 |
| IP | 94.158.245.52 | BazarLoader C2 — HTTPS port 443 |

### Host IOCs

| Type | Value | Description |
|---|---|---|
| SHA256 | eed363fc4af7a9070d69340592dcab7c78db4f90710357de29e3b624aa957cf8 | BazarLoader DLL |
| File size | 284,816 bytes | BazarLoader DLL |
| File type | 64-bit Windows DLL | Requires explicit execution |
| URI pattern | /bmdff/ | TA551 campaign signature — active for several weeks |

### Firewall / DNS Block List

```
# Block at perimeter firewall
194.62.42.206
167.172.37.9
94.158.245.52

# Block at DNS
simpsonsavingss.com

# Hunt in proxy logs — URI pattern
/bmdff/
```

---

## 5. Malware Analysis

### BazarLoader Overview
BazarLoader (also known as BazaLoader or Team9Backdoor) is a loader malware used to deliver second-stage payloads including Cobalt Strike, ransomware (Ryuk/Conti), and DarkVNC remote access tool. It is closely associated with the TrickBot group and is typically delivered via TA551 (Shathak) phishing campaigns.

### TA551 (Shathak) Campaign Pattern
TA551 consistently uses the following delivery chain:
- Phishing email with password-protected zip
- Zip contains malicious Word/Excel document
- Document uses VBA macro to download payload DLL
- DLL retrieved via URL path containing `/bmdff/` (campaign-specific pattern)
- DLL executed to establish C2

The `/bmdff/` URI pattern was confirmed active for several weeks prior to this exercise, meaning multiple organizations were likely targeted by the same infrastructure.

### Sandbox Analysis
- **Triage:** https://tria.ge/211004-vc7nsaggej
- **ANY.RUN (email sample):** https://app.any.run/tasks/66e29996-8ad2-4d3e-b6a2-c74306b5ef3b/
- Both confirm BazarLoader behavior consistent with TA551 campaign

### Why the DLL Didn't Auto-Execute
BazarLoader DLLs require explicit execution (via `rundll32.exe` or similar) — they do not auto-run upon download. This means the user or macro must explicitly trigger execution. In this case, the macro in the Word document handled this step.

---

## 6. MITRE ATT&CK Mapping

| ID | Technique | Evidence |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Password-protected zip via email |
| T1059.005 | Command and Scripting Interpreter: VBA | Word document macro execution |
| T1105 | Ingress Tool Transfer | HTTP GET for BazarLoader DLL |
| T1027 | Obfuscated Files or Information | Password-protected zip obscures payload |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP DLL retrieval |
| T1573.001 | Encrypted Channel | HTTPS C2 to 167.172.37.9 and 94.158.245.52 |
| T1041 | Exfiltration Over C2 Channel | C2 beaconing post-infection |

---

## 7. Detection Rules (Splunk SPL)

### Rule 1 — TA551 URI Pattern Detection (T1105)
```spl
index=network http.request.method=GET
  uri="*/bmdff/*"
| stats count by src_ip, dest_ip, uri, http.host
```
**Logic:** The `/bmdff/` path is a known TA551 campaign signature. Any match is high-confidence TA551 activity — no false positives expected.

### Rule 2 — DLL Download via HTTP from External IP (T1105)
```spl
index=network http.request.method=GET
| eval is_dll=if(match(uri,"\.dll$") OR match(uri,"date[0-9]+"),1,0)
| where is_dll=1
| eval dest_internal=if(match(dest_ip,"^(10\.|192\.168\.)"),1,0)
| where dest_internal=0
| stats count by src_ip, dest_ip, uri, http.host
```
**Logic:** DLL downloads from external IPs via HTTP are almost always malicious. Combined with URL patterns like `date1`, `date2` (TA551 naming convention) gives near-zero false positives.

### Rule 3 — BazarLoader C2 Beaconing (T1573.001)
```spl
index=network ssl.handshake.type=1
  (dest_ip="167.172.37.9" OR dest_ip="94.158.245.52")
| stats count by src_ip, dest_ip, _time
| bucket _time span=5m
| streamstats window=6 current=t stdev(count) as regularity by src_ip
| where regularity < 2
```
**Logic:** Regular HTTPS beaconing to known BazarLoader C2 IPs. Low standard deviation confirms machine-like beaconing vs human browsing.

### Rule 4 — Password-Protected Zip from External Email (T1027 + T1566.001)
```spl
index=email attachment_name="*.zip"
| eval suspicious=if(match(subject,"(invoice|document|payment|report|scan)"),1,0)
| where suspicious=1
| stats count by sender, recipient, subject, attachment_name
```
**Logic:** Password-protected zips with invoice/document subject lines are a primary TA551 delivery mechanism. Email gateway detection catches this before the user opens anything.

---

## 8. Analyst Notes

**Campaign Persistence:** The `/bmdff/` URI pattern was active for several weeks prior to this capture — indicating this is not an isolated incident but part of an ongoing campaign. Organizations should hunt historically across all proxy logs for this pattern.

**No Follow-on Payload:** This capture shows no Cobalt Strike or DarkVNC follow-up — unusual for TA551 BazarLoader infections. This may indicate the capture ended before the second stage, the C2 did not respond with a payload, or the attacker chose not to deploy further tools on this target.

**DLL Execution Requirement:** The BazarLoader DLL requires explicit execution. This means endpoint controls (application whitelisting, blocking `rundll32.exe` from executing DLLs from user-writable locations) would have prevented infection even after the DLL was downloaded.

**TA551 Attribution Confidence:** High. Three indicators confirm TA551: password-protected zip delivery, `/bmdff/` URI pattern (campaign-specific), and BazarLoader as the payload (TA551's primary loader during this period).

---

## 9. Immediate Response Recommendations

| Priority | Action |
|---|---|
| P0 | Isolate DESKTOP-KKITB6Q (10.9.10.102) |
| P0 | Block IPs: 194.62.42.206, 167.172.37.9, 94.158.245.52 |
| P0 | Block domain: simpsonsavingss.com at DNS |
| P1 | Hunt `/bmdff/` in all proxy logs for past 30 days |
| P1 | Check all hosts for rundll32.exe execution of DLLs from temp directories |
| P1 | Review emails to other users for similar password-protected zips |
| P2 | Submit DLL hash to internal threat intel platform |
| P2 | Alert email gateway to block password-protected zips from external senders |
| P3 | Deploy detection rules 1–4 to SIEM |

---

## 10. Tools Used

| Tool | Purpose |
|---|---|
| Wireshark | Primary PCAP analysis |
| VirusTotal | Hash and domain reputation |
| Triage sandbox | BazarLoader DLL analysis |
| ANY.RUN | Email sample sandbox analysis |
| MITRE ATT&CK Navigator | TTP mapping |

---

## References
- Exercise: https://www.malware-traffic-analysis.net/2021/09/10/index.html
- BazarLoader MITRE: https://attack.mitre.org/software/S0534/
- TA551 MITRE: https://attack.mitre.org/groups/G0127/
- Triage analysis: https://tria.ge/211004-vc7nsaggej
- ANY.RUN sample: https://app.any.run/tasks/66e29996-8ad2-4d3e-b6a2-c74306b5ef3b/

---
*Himanshu Kumar Modi | Associate at PwC India | SOC Analyst in Training*
*[LinkedIn](https://www.linkedin.com/in/himanshu-kumar-modi-063b88239) | [Cybersecurity Portfolio](https://github.com/himanshumodi3108/cybersec-portfolio)*