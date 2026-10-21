# VULN-007 — Admin ForeignKeyRawIdWidget staff IDOR → auth.User enumeration

**Software**: Django
**Repository**: https://github.com/django/django
**Affected version**: 6.2.0a0 (targets/django/django/__init__.py) — commit-pinned: no tagged release
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: 9e06baf2e4dd17834b5deaf3a3e6ae3bff2fcf26
**Validated at**: 2026-09-30T07:59Z

## Preconditions
- A low-privilege `is_staff` user with `add`/`change`/`view` on `labapp.article`
  only, and **no** permission on `auth.User`. Provisioned via the app ORM
  (`User.objects.create` + `user_permissions.add`) inside the app container.
- A "hidden" superuser (`victimsu_<suffix>`) created to prove the attack reaches
  accounts the attacker is 403-forbidden from viewing.
- `ArticleAdmin.raw_id_fields = ["author"]` with `Article.author → auth.User`
  (present in the lab harness admin).

## Request
See `request.http` (POST `/admin/labapp/article/add/` with `author=<pk>` and a
blank `title` to force a bound re-render). The decisive parameter is `author=<pk>`.

## Response
See `response.txt` — the author-widget region of the bound re-render. It contains
`<strong><a href="/admin/auth/user/<pk>/change/">USERNAME</a></strong>`, i.e. the
str() (username) of the arbitrary auth.User pk the attacker supplied.

## Observation
Exactly as the static finding predicted. The attacker session:
- received **HTTP 403** on `GET /admin/auth/user/` (no view permission), yet
- recovered **all 7 usernames** (admin, staff, alice, and the freshly-created
  low-priv + hidden-superuser accounts) by iterating `author=1..N`, including the
  hidden superuser `victimsu_75fbfa57` it could not otherwise see.

Confirms `label_and_url_for_value` (`contrib/admin/widgets.py:214`) does an
unscoped `_default_manager.get(pk=<attacker>)` and renders `str(obj)` (`:231`)
with no `has_view_permission` gate — the exact authorization asymmetry vs the
hardened `AutocompleteJsonView` (`contrib/admin/views/autocomplete.py:121-123`).

## Side effects
Creates two accounts per run (`mod_<suffix>`, `victimsu_<suffix>`) via the ORM.
Random suffixes keep runs independent. No Articles are created (every POST fails
validation on the blank `title`). Cleanup (optional):
`docker exec -i cvehunterlab_django_app python - <<'PY'` … `User.objects.filter(username__startswith="mod_").delete(); User.objects.filter(username__startswith="victimsu_").delete()` `PY`.

## Research & references
- OWASP WSTG-ATHZ-04 (IDOR) and WSTG-ATHZ-02 (bypassing authorization schema) —
  test procedure: access an object reference the account should not be authorized
  for and observe disclosure. Applied by supplying arbitrary `auth.User` PKs.
- OWASP "Insecure Direct Object Reference Prevention" cheat sheet — the control
  that is missing here is a per-object authorization check at the data-access point.
- Django admin authorization model (per-model `has_view_permission`); the sibling
  `AutocompleteJsonView` is Django's own reference implementation of the gate that
  `label_and_url_for_value` omits.

## If FAILED
n/a — CONFIRMED.
