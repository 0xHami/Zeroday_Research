# Frappe LMS 2.40.0 – Public Access to Instructor Media in Course Details and Quizzes

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
| Vendor acknowledgement | No |
| PoC / exploit | https://gist.github.com/0xHamy/83abdce4a472b80ecae8c436929aeecf |
| Credit | 0xhamy |
| Date published | 2025-12-14T03:12:40.391609+00:00 |
| Last modified | 2026-03-08T08:37:08.336203+00:00 |

---

# Description

Frappe LMS version 2.40.0 is affected by an access control vulnerability where **media uploaded by instructors to course details and quizzes is publicly accessible** to unauthenticated users.

This includes:

- Media uploaded to **unpublished course details** (e.g. course description).
- Media uploaded to **quizzes** used within courses.

All such media is stored under `/files/` and is accessible without authentication if the filename or URL is known or guessed.

## Vulnerability Details
Two related behaviors share the same root cause: instructor-uploaded media for course and quiz content is served from a publicly accessible file endpoint without any authorization checks.

1. **Course details (including unpublished courses)**  
   - When an instructor creates or edits a course via `/lms/courses/new/edit` or `/lms/courses/COURSE_NAME/edit`, media uploaded to fields like **Course description** is stored under `/files/`.
   - Even if the course is never published, the media remains accessible via direct URL.

2. **Quiz media**  
   - Media attached to quiz questions or quiz content is similarly uploaded under `/files/`.
   - These files are accessible without authentication.

Since quiz content may include exam questions, diagrams, or answer hints, and course detail media may be intended for limited audiences, this leads to a significant information disclosure issue.

# Steps to Reproduce

### A. Course Details Media (Unpublished Course)

1. **Log in as an instructor.**  
   - Navigate to `/lms/courses`.

2. **Create a new course and upload media to course details.**  
   - Open: `/lms/courses/new/edit`  
   - Fill in the required fields.  
   - In the **Course description** (or a similar rich-text field), upload an image or media file.  
   - Note that the file is stored under a URL such as:  
     `/files/FILENAME.ext`

3. **Ensure the course is unpublished.**  
   - Leave the **“Published”** option unchecked.

4. **Access the media without authentication.**  
   - Log out (or open an unauthenticated browser session).  
   - Open:  
     `http://localhost:8000/files/FILENAME.ext`  
   - The media is accessible despite the course being unpublished and no active session.

### B. Quiz Media

1. **Log in as an instructor and create a quiz.**  
   - Navigate to `/lms/quizzes` and click the **"Create"** button in the top-right corner.  

2. **Add a quiz question with media.**  
   - In the new window that opens (e.g. `/lms/quizzes/Test`), click **"New Question"** to create a question for the quiz.  
   - In the **Question** text area, upload one or more media files.  
   - These files are uploaded to `/files/`, making them globally accessible by URL.  
   - Click **"Save"** to store the question.

3. **Access quiz media without authentication.**  
   - Log out or use an unauthenticated session.  
   - Navigate directly to:  
     `http://localhost:8000/files/FILENAME.ext`  
   - The media is publicly accessible without any authentication or authorization.

# Impact
- **Exposure of quiz/exam content**: Images or media embedded in quizzes may include question statements, diagrams, or other sensitive assessment material that can be accessed in advance by unauthorized users.
- **Leakage of unpublished course information**: Unpublished course branding, diagrams, or internal assets become accessible even before the course is officially released.
- **Business and academic integrity risk**: Pre-exposure of exam content undermines fairness, may compromise course integrity, and can have reputational and compliance impacts.

Because quizzes often contain assessment content and may be reused, the **worst-case confidentiality impact is high**.

# Recommendation
- Enforce **authentication and authorization checks** for all media served under `/files/`, especially:
  - Course details media.
  - Quiz-related media.
- Restrict file access based on:
  - Course publication status.
  - User role (student/instructor/admin).
  - Enrollment status for the corresponding course.
- Serve files via a permission-aware endpoint instead of direct static URLs.
- Consider using:
  - **Per-course scoped storage** for media.
  - **Signed, expiring URLs** that validate the user’s permissions at request time.
