# Frappe LMS 2.40.0 – Access to Unpublished Courses via Predictable Slugs

| Field | Value |
| --- | --- |
| Vulnerability name | Improper Access Control |
| Vulnerability type | software |
| Product name | Frappe LMS |
| Product vendor | Frappe |
| Product version | 2.40.0 |
| Product link | https://github.com/frappe/lms |
| Product environment | web |
| Severity | High |
| CVSS score | 7.5 |
| CVSS vector | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| Affected assets | 10 |
| Affected users | 50000 |
| Date of reporting | Nov 27, 2025 |
| Vendor acknowledgement | No |
| PoC / exploit | https://gist.github.com/0xHamy/d978d5dc2730b2b2c10649255f067a34 |
| Credit | 0xhamy |
| Date published | 2025-12-14T03:06:31.099032+00:00 |
| Last modified | 2025-12-14T03:15:50.767968+00:00 |

---

# Description

Frappe LMS version 2.40.0 is vulnerable to an **access control bypass** where **unpublished course content remains accessible** through predictable slug-based URLs.

Although direct access to an unpublished course page (e.g. `/lms/courses/linux-administration/`) correctly redirects to the courses listing, an attacker can still access course content and lessons via URLs such as `/lms/courses/linux-administration/learn/1-1`, even if the course is not published.

## Vulnerability Details
The application enforces publication checks on the **course overview endpoint**, but fails to consistently enforce them on **lesson/learning endpoints** under the `/learn/[chapter]-[item]` structure.

Key points:

- Unpublished courses should not be accessible to students or unauthenticated users.
- The slug pattern `/lms/courses/[COURSE_NAME]/learn/1-1` exposes chapter and lesson content even when the course is unpublished.
- A student can also **enroll into an unpublished course** by accessing these direct URLs.

This constitutes a broken access control vulnerability. It's a bypass for CVE-2025-11281.

# Steps to Reproduce
1. **Log in as an instructor.**
   - Navigate to the courses page:  
     `/lms/courses`

2. **Create a new course.**
   - Create a course (e.g. `linux-administration`).
   - Add at least one chapter and one lesson or assignment in Chapter 1.

3. **Ensure the course is unpublished.**
   - In the course settings, **leave the “Published” checkbox unchecked**.

4. **Attempt to access the course overview (blocked as expected).**
   - As a **student** or unauthenticated user, open:  
     `/lms/courses/linux-administration/`  
   - You are redirected to the courses page (unpublished course is not directly visible).

5. **Bypass using the predictable lesson slug.**
   - As a **student** or unauthenticated user, open:  
     `/lms/courses/linux-administration/learn/1-1`  
   - Observe that chapter and lesson names and content are accessible even though the course is unpublished.

6. **Test with other course names.**
   - For any known course slug, access:  
     `/lms/courses/[COURSE_NAME]/learn/1-1`  
   - You may be able to view unpublished course content and in some cases enroll or continue learning.

# Impact
- **Exposure of unpublished course content**: Draft or embargoed material can be accessed before it is intended to be released.
- **Leakage of lesson/assignment content**: Attackers can view course structure, lessons, assignments, and potentially exam-like content.
- **Predictable enumeration**: Slugs like `learn/1-1`, `learn/1-2`, etc. allow easy enumeration of course content once the course name is known.
- **Business/academic integrity risk**: Early or unauthorized access to course materials can undermine course schedules, exam integrity, or paid content models.

This is a **high-impact confidentiality issue**, as it undermines the core publish/unpublish model of the LMS.

# Recommendation
- Enforce **publication and authorization checks** consistently across **all course-related endpoints**, including:
  - `/lms/courses/[COURSE_NAME]/learn/*`
  - Any API endpoints that return course structure or content.
- Ensure that:
  - Unpublished courses are inaccessible to students and unauthenticated users.
  - Only instructors and admins can access unpublished course content.
- Avoid relying solely on slug visibility or redirects on the course overview page; apply checks at the **content/lesson level**.
- Implement centralized authorization middleware for all course routes to ensure consistent behavior.
