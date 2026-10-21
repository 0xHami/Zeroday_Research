# VULN-007 — Admin `ForeignKeyRawIdWidget` discloses any related object's `str()` with no permission check (staff IDOR → `auth.User` enumeration)

| | |
|---|---|
| **Vulnerability ID** | VULN-007 (origin DJ-001) |
| **Software** | Django |
| **Repository** | https://github.com/django/django |
| **Affected version** | 6.2.0a0 (dev/`main`; commit-pinned, no tagged release) |
| **Commit** | `9e06baf2e4dd17834b5deaf3a3e6ae3bff2fcf26` |
| **Severity** | Medium — **CVSS 3.1 4.3** `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (→ 6.4 `C:H` if the related model's `__str__` exposes more than a username) |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Any `is_staff` user with `add`/`change` on a model that has a `raw_id_fields` FK; **no** permission on the related (target) model. In the lab this role is obtained by provisioning a staff user with only `labapp.article` permissions. |
| **Attacker gains** | Reads the `str()` (here: the username) of arbitrary rows of a model they have zero rights on — full `auth.User` enumeration, including superusers. |

## Summary

Django's admin renders a `ForeignKeyRawIdWidget` for any FK listed in a
`ModelAdmin.raw_id_fields`. When such a form is re-rendered *bound* — which
happens on any validation error — the widget looks up the FK target by the
attacker-supplied primary key **using the model's default manager, with no
authorization check**, and renders that object's string representation into the
HTML. A low-privilege staff user who can open one model's add form can therefore
read the `str()` of any object of the *related* model, regardless of their
permissions on it. Because the lab's `Article.author` points at `auth.User`
(whose `__str__` is the username), a staff user restricted to the `labapp`
application enumerates every account's username — including superusers — by
walking primary keys. This was proven end-to-end against the running lab: the
attacker received **HTTP 403** on the user changelist yet still recovered all
usernames, including a hidden superuser.

## How it works (mechanism & code trace)

**Entry point.** The admin add/change view builds a `ModelForm`; for the
`author` field, `ArticleAdmin.raw_id_fields = ["author"]`
(`setup/harness/labapp/admin.py:33`) causes
`ModelAdmin.formfield_for_foreignkey` to attach a `ForeignKeyRawIdWidget`
(`targets/django/django/contrib/admin/widgets.py`). The form is submitted to
`POST /admin/labapp/article/add/`.

**Source of taint.** On a bound form the widget's value is the raw POST string
for `author`. `ForeignKeyRawIdWidget.get_context`
(`contrib/admin/widgets.py:164-196`) passes that value into
`label_and_url_for_value` at line 190-193.

**Sink.** `label_and_url_for_value` (`contrib/admin/widgets.py:211-231`):

```python
def label_and_url_for_value(self, value):
    key = self.rel.get_related_field().name
    try:
        obj = self.rel.model._default_manager.using(self.db).get(**{key: value})  # :214
    except (ValueError, self.rel.model.DoesNotExist, ValidationError):
        return "", ""
    ...
    return Truncator(obj).words(14), url                                          # :231
```

Line **214** is an unscoped lookup on the *related* model (`auth.User`) keyed on
the attacker-chosen `value`; line **231** renders `str(obj)` (the username) into
the page. No `has_view_permission`, `has_change_permission`, or queryset scoping
is applied anywhere between the POST and this render.

**The exact defect.** The authorization check that governs "may this staff user
read a `str()` of that related object?" is simply absent. Django *knows* how to
do this: the sibling autocomplete endpoint enforces it —
`AutocompleteJsonView.has_perm` (`contrib/admin/views/autocomplete.py:121-123`)
returns `related_admin.has_view_permission(request, obj)` before returning any
related-object label. `label_and_url_for_value` performs the semantically
identical read (related object → label) without that gate.

**Why the framework doesn't save it.** Admin permission checks are per-view
(`has_add_permission` on the Article add view) and per-model; there is no
cross-model check when one model's form *references* another. `raw_id_fields`
was designed for large related tables where a `<select>` is impractical, and the
"show the label of the currently-selected object" convenience calls straight
into the manager. The `try/except` only catches lookup failures (bad/absent PK),
never a permission failure — because no permission is ever consulted.

## Why it is a vulnerability (reasoning)

The admin's security model is that a staff user sees only what their assigned
model permissions allow; `auth.User` is a separate, typically highly-restricted
model. The trust boundary being crossed is **model-level authorization**: a user
with rights *only* on `labapp.article` must not be able to read `auth.User`
rows. The widget violates exactly this: it turns "I can add an Article" into "I
can read the username of any User by PK." The behavior is not by-design — the
existence of the hardened `AutocompleteJsonView` sibling shows upstream intent to
gate related-object reads; this path just misses it. The dynamic result makes the
argument unarguable: the same session that is answered **403 Forbidden** on
`GET /admin/auth/user/` nonetheless extracts every username (including a superuser
account the attacker created blind and could not list) through the widget. The
attacker's *intended* capability (edit articles) and their *actual* capability
(enumerate all users) diverge — the definition of broken access control.

## Reproduction

From a clean lab (`docker compose -p cvehunterlab_django up -d`; see manifest):

1. **Provision the attacker & victim** (the exploit does this via the app ORM):
   a staff user `mod_<suffix>` with only `add/change/view_article`, and a hidden
   superuser `victimsu_<suffix>`.
2. **Run it:** `./run.sh` (uses the shared venv; `BASE_URL` defaults to the
   manifest's `http://localhost:20796`).
3. The exploit logs in as `mod_<suffix>`, confirms `GET /admin/auth/user/` →
   **403**, then for each PK POSTs the add form with `author=<pk>` and a blank
   `title`. The decisive request (`request.http`):

   ```
   POST /admin/labapp/article/add/ HTTP/1.1
   Content-Type: application/x-www-form-urlencoded
   csrfmiddlewaretoken=<t>&author=5&title=&slug=&body=&category=&metadata=%7B%7D&...
   ```

4. **Observable proof:** the response contains
   `<strong><a href="/admin/auth/user/5/change/">victimsu_<suffix></a></strong>`
   (`response.txt`), and the transcript prints
   `[PROOF] author=5 leaked username -> 'victimsu_<suffix>' <== HIDDEN SUPERUSER`
   followed by `[OK] exploit confirmed …`. Expected exit code 0. Full run in
   `run.log`.

## Impact

Horizontal information disclosure / IDOR. A low-privilege staff user reads data
from a model they cannot otherwise access. In the lab this is the **complete
`auth.User` username list, including superusers** — a direct recon primitive:

- **Blast radius:** every row of any model reachable as a `raw_id_fields` FK
  target. The same widget class backs `ManyToManyRawIdWidget`, so raw-id M2M
  relations are equally affected. If a related model's `__str__` returns more
  than a username (full name, email, internal identifier), confidentiality
  impact rises to `C:H`.
- **Post-auth, staff-only, read-only** — hence Medium, not High.
- **Chaining:** the enumerated superuser usernames feed credential-stuffing /
  password-spray against the (by-design rate-limit-free) login and password-reset
  flows, and select victims for VULN-009 (reset host-poisoning, were the site
  unpinned). It is one of a cluster of staff-side recon gaps with VULN-012
  (admindocs route/template disclosure), VULN-016 (`/admin/r/` existence oracle),
  and VULN-030 (`?o=` sort of hidden columns).

## Suggested fix

Gate the related-object read on the viewer's permission, mirroring
`AutocompleteJsonView`. In `contrib/admin/widgets.py`,
`label_and_url_for_value` (thread `request` in via `formfield_for_foreignkey`,
which already has it):

```python
def label_and_url_for_value(self, value):
    key = self.rel.get_related_field().name
    try:
        obj = self.rel.model._default_manager.using(self.db).get(**{key: value})
    except (ValueError, self.rel.model.DoesNotExist, ValidationError):
        return "", ""
    related_admin = self.admin_site._registry.get(self.rel.model)
    if related_admin is None or not related_admin.has_view_permission(self.request, obj):
        return "", ""          # deny by default; do not render str(obj)
    ...
```

Apply the identical gate to `ManyToManyRawIdWidget.label_and_url_for_value`.
Principle: authorization must be enforced at the data-access point, not delegated
to the caller — and it must be a per-object *allowlist* (deny unless permitted),
matching the existing autocomplete implementation.

## References

- OWASP WSTG-ATHZ-04 — Testing for Insecure Direct Object References; WSTG-ATHZ-02
  — Testing for Bypassing Authorization Schema. Technique used: request an object
  reference (arbitrary `auth.User` PK) the account is not authorized for and
  confirm disclosure.
- OWASP "Insecure Direct Object Reference Prevention" cheat sheet — the missing
  control is a per-object access check at the point of data retrieval.
- Django source: hardened sibling `contrib/admin/views/autocomplete.py:121-123`
  (`has_perm` gate) vs the ungated `contrib/admin/widgets.py:211-231`.
- Related upstream tickets touch only performance on this widget
  ([#9258](https://code.djangoproject.com/ticket/9258),
  [#29294](https://code.djangoproject.com/ticket/29294)); none ties the unscoped
  lookup to the missing permission check — this authorization gap appears novel.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 55 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `Django admin ForeignKeyRawIdWidget label_and_url_for_value permission check related object disclosure` — web-search quota exhausted; verified instead by direct fetch of the two upstream tickets that touch this widget: Trac #9258 (2008, switched the label lookup to `_default_manager`; a manager-choice bugfix, no permission discussion) and Trac #29294 (N+1 query performance, closed wontfix 2022, no permission discussion).
2. GitHub Advisory Database query `ForeignKeyRawIdWidget` — single hit GHSA-2m34-jcjv-45xf / CVE-2020-13596 (XSS in this widget's rendered label); not an authorization issue.
3. GitHub Advisory Database query `django raw_id_fields` — 0 advisories.
4. Django official security-release archive (docs.djangoproject.com/en/dev/releases/security/) read in full — only CVE-2020-13596 (XSS, same widget) and CVE-2010-4534 (changelist filter FK traversal leak, different component) are adjacent; no entry about related-object label disclosure through `raw_id_fields`.
5. Django admin reference docs — `autocomplete_fields` explicitly states users "must have the view or change permission to the related object ... to avoid unauthorized data disclosure"; the `raw_id_fields` section carries no permission requirement at all.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2020-13596 / GHSA-2m34-jcjv-45xf — XSS via the same `ForeignKeyRawIdWidget` (escaping defect in the rendered link), not a missing permission check.
- CVE-2010-4534 — admin changelist filter allowed FK traversal in the query string to leak related data; different component (changelist `lookup_allowed`), fixed in 2010.
- Django docs for `ModelAdmin.autocomplete_fields` — documents the view/change-permission gate on the sibling `AutocompleteJsonView`, showing upstream intent but not acknowledging the gap in the raw-id widget.

**Reasoning:** No CVE, GHSA, security release, or Trac ticket ties `label_and_url_for_value`'s unscoped `_default_manager` lookup to a missing per-model permission check; the only public items on this widget are an XSS fix and performance tickets. Confidence is kept moderate because (a) Django's default `<select>` FK widget also renders every related object's `str()` to any staff user with add/change permission on the referencing model, so upstream may regard related-label visibility as by-design rather than a vulnerability; (b) the Trac full-text search endpoint returned HTTP 403 and the web-search quota was exhausted, so a low-visibility ticket could exist; (c) a private report could already be with the Django security team.
