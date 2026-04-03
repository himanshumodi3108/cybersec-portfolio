# Detection Queries — BazarLoader / TA551 Campaign
**Case:** 2021-09-10 BazarLoader via TA551
**Analyst:** Himanshu Kumar Modi | **Date:** 2026-03-25

---

## Query 1 — TA551 /bmdff/ URI Pattern (T1105)
**Observed:** GET /bmdff/BhoHsCtZ/.../date1?BNLv65=pAAS
```spl
index=network http.request.method=GET uri="*/bmdff/*"
| stats count by src_ip, dest_ip, uri, http.host
```
**Logic:** `/bmdff/` is a TA551 campaign-specific URI pattern. Any match = confirmed TA551 activity.

---

## Query 2 — DLL Download via HTTP (T1105)
**Observed:** 64-bit DLL retrieved via HTTP GET disguised under date-pattern URL
```spl
index=network http.request.method=GET
| eval is_dll=if(match(uri,"\.dll$") OR match(uri,"date[0-9]+"),1,0)
| where is_dll=1
| eval dest_internal=if(match(dest_ip,"^(10\.|192\.168\.)"),1,0)
| where dest_internal=0
| stats count by src_ip, dest_ip, uri, http.host
```

---

## Query 3 — BazarLoader C2 Beaconing (T1573.001)
**Observed:** HTTPS beaconing to 167.172.37.9 and 94.158.245.52 port 443
```spl
index=network ssl.handshake.type=1
  (dest_ip="167.172.37.9" OR dest_ip="94.158.245.52")
| bucket _time span=5m
| stats count by src_ip, dest_ip, _time
| streamstats window=6 current=t stdev(count) as regularity by src_ip
| where regularity < 2
```

---

## Query 4 — Password-Protected Zip from External Email (T1027)
**Observed:** TA551 delivers payload in password-protected zip via phishing
```spl
index=email attachment_name="*.zip"
| eval suspicious=if(match(subject,"(invoice|document|payment|report|scan)"),1,0)
| where suspicious=1
| stats count by sender, recipient, subject, attachment_name
```