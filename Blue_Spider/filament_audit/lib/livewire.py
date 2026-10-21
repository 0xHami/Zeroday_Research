"""
Minimal Livewire 3 client for driving Filament components over POST /livewire/update.

Why this exists
---------------
Every Filament component interaction (form submit/validation, table
search/sort/paginate/bulk, action modals, file uploads, schema-component method
calls) flows through the single endpoint ``POST /livewire/update``. Its request
body carries the component's *snapshot* — a JSON blob that the server
re-checksums with the app's ``APP_KEY``. A raw hand-built ``curl`` cannot forge a
valid snapshot, so dynamic validation must:

  1. ``GET`` the hosting page and lift the server-produced ``wire:snapshot`` (it
     is already correctly checksummed),
  2. replay that snapshot **byte-for-byte** in the update request (so the
     checksum still validates),
  3. place tampered values in ``updates`` — this works because Filament's public
     Livewire properties (``$data``, ``$tableRecordsPerPage``,
     ``$selectedTableRecords`` ...) are **not** ``#[Locked]``,
  4. invoke server methods via ``calls``.

The server answers with a *new* snapshot (for the next round-trip) plus
``effects`` (HTML diff, returns, dispatches). We keep the latest snapshot so a
sequence of interactions can be chained like a real browser session.

This is library scaffolding for the exploits, not a finding target.
"""

from __future__ import annotations

import html
import json
import re
import secrets
from typing import Any

import requests


class LivewireError(RuntimeError):
    pass


class LivewireComponent:
    """One Livewire component instance on a page: its snapshot + id, plus the
    client used to talk to the server. Mutating calls update ``self.snapshot``."""

    def __init__(self, client: "LivewireClient", wire_id: str, snapshot: str, name: str):
        self.client = client
        self.id = wire_id
        self.snapshot = snapshot  # the raw JSON *string* (as the server emitted it)
        self.name = name

    # -- snapshot accessors ------------------------------------------------
    def snapshot_obj(self) -> dict:
        return json.loads(self.snapshot)

    def data(self) -> Any:
        """The component's public ``$data`` property, de-tupled.

        Livewire dehydrates arrays as ``[value, {"s":"arr"}]`` tuples; this
        strips the metadata so callers see plain Python values.
        """
        obj = self.snapshot_obj()
        return _strip_meta(obj["data"].get("data"))

    def memo(self) -> dict:
        return self.snapshot_obj().get("memo", {})

    # -- the round-trip ----------------------------------------------------
    def message(
        self,
        calls: list[dict] | None = None,
        updates: dict | None = None,
    ) -> tuple[dict, "LivewireComponent"]:
        """Send one ``/livewire/update`` message for this component.

        ``updates`` is a flat dict of dotted Livewire paths → new values, e.g.
        ``{"data.author": 2}`` or ``{"tableRecordsPerPage": "all"}``. ``calls``
        is a list of ``{"path","method","params"}`` dicts.

        Returns ``(response_json, self)`` and refreshes ``self.snapshot`` from
        the server's reply so the next call chains correctly.
        """
        payload = {
            "_token": self.client.csrf,
            "components": [
                {
                    "snapshot": self.snapshot,
                    "updates": updates or {},
                    "calls": calls or [],
                }
            ],
        }
        resp = self.client.session.post(
            f"{self.client.base}/livewire/update",
            data=json.dumps(payload),
            headers={
                "Content-Type": "application/json",
                "X-Livewire": "true",
                "X-CSRF-TOKEN": self.client.csrf,
                "Accept": "text/html, application/xhtml+xml",
                "Referer": self.client.last_url or self.client.base,
            },
            timeout=self.client.timeout,
        )
        self.client.last_response = resp
        if resp.status_code != 200:
            raise LivewireError(
                f"/livewire/update -> HTTP {resp.status_code}\n{resp.text[:2000]}"
            )
        body = resp.json()
        comp = body["components"][0]
        # Refresh our snapshot for the next round-trip.
        self.snapshot = comp["snapshot"]
        return body, self

    # -- convenience wrappers ---------------------------------------------
    def call(self, method: str, *params: Any, updates: dict | None = None) -> dict:
        body, _ = self.message(
            calls=[{"path": "", "method": method, "params": list(params)}],
            updates=updates,
        )
        return body

    def set(self, updates: dict) -> dict:
        """Push property updates with no method call (re-renders the component)."""
        body, _ = self.message(calls=[], updates=updates)
        return body

    def call_schema_method(self, component_key: str, method: str, *params: Any,
                           updates: dict | None = None) -> dict:
        """Invoke a schema component's ``#[ExposedLivewireMethod]`` via the
        generic dispatcher ``callSchemaComponentMethod(key, method, args)``."""
        return self.call("callSchemaComponentMethod", component_key, method, list(params),
                         updates=updates)

    def upload_file(self, state_path: str, filename: str, content: bytes,
                    content_type: str, is_multiple: bool = False) -> list[str]:
        """Drive Livewire's 3-step file upload for a FileUpload field.

        1. ``_startUpload`` → server dispatches ``upload:generatedSignedUrl`` with a
           signed ``/livewire/upload-file`` URL.
        2. POST the bytes there as multipart ``files[]`` (with the CSRF token).
        3. ``_finishUpload`` → the field's state now references the temp upload.

        Returns the temp filenames. The stored name later takes the CLIENT extension
        (``filename``), which is the heart of VULN-002.
        """
        body = self.call("_startUpload", state_path,
                         [{"name": filename, "size": len(content), "type": content_type}],
                         is_multiple)
        url = None
        for d in body["components"][0].get("effects", {}).get("dispatches", []):
            if d.get("name") == "upload:generatedSignedUrl":
                url = d["params"]["url"]
        if not url:
            raise LivewireError("no signed upload URL returned by _startUpload")
        r = self.client.session.post(
            url,
            files={"files[]": (filename, content, content_type)},
            headers={"X-CSRF-TOKEN": self.client.csrf},
            timeout=self.client.timeout,
        )
        if r.status_code != 200:
            raise LivewireError(f"/livewire/upload-file -> HTTP {r.status_code}: {r.text[:500]}")
        paths = r.json()["paths"]
        self.call("_finishUpload", state_path, paths, is_multiple)
        return paths


class LivewireClient:
    def __init__(self, base: str, timeout: int = 120):
        self.base = base.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "cvehunter-livewire/1.0"})
        self.csrf: str | None = None
        self.timeout = timeout
        self.last_url: str | None = None
        self.last_response: requests.Response | None = None

    # -- auth --------------------------------------------------------------
    def login_admin_panel(self, email: str, password: str, panel: str = "admin",
                          totp_secret: str | None = None) -> None:
        """Authenticate against a Filament panel login (Livewire form submit)."""
        login_url = f"{self.base}/{panel}/login"
        comp = self.get_component(login_url, component_name=None)
        # Filament login form binds email/password under $data.
        comp.message(
            calls=[{"path": "", "method": "authenticate", "params": []}],
            updates={"data.email": email, "data.password": password, "data.remember": False},
        )
        # Follow up: the login response issues a redirect effect; the session
        # cookie is now set on self.session. Verify by hitting the panel root.
        r = self.session.get(f"{self.base}/{panel}", allow_redirects=False,
                             timeout=self.timeout)
        if r.status_code not in (200, 302):
            raise LivewireError(f"login check: unexpected {r.status_code}")
        # If still redirected to /login, auth failed (unless MFA).
        if r.status_code == 302 and "/login" in r.headers.get("Location", ""):
            raise LivewireError("login failed — redirected back to /login")

    # -- page fetch --------------------------------------------------------
    def fetch(self, url: str) -> str:
        r = self.session.get(url, timeout=self.timeout)
        self.last_url = url
        r.raise_for_status()
        html_text = r.text
        self._extract_csrf(html_text)
        return html_text

    def _extract_csrf(self, html_text: str) -> None:
        m = re.search(r'name="csrf-token"\s+content="([^"]+)"', html_text)
        if m:
            self.csrf = m.group(1)

    def get_component(self, url: str, component_name: str | None = None,
                      index: int = 0) -> LivewireComponent:
        """Fetch ``url`` and return a Livewire component found on the page.

        ``component_name`` filters by the component's ``name`` memo (e.g.
        ``"file-upload"``); otherwise the ``index``-th component is returned.
        """
        html_text = self.fetch(url)
        comps = self.parse_components(html_text)
        if not comps:
            raise LivewireError(f"no Livewire components found at {url}")
        if component_name:
            for c in comps:
                if c.name == component_name:
                    return c
            raise LivewireError(
                f"component '{component_name}' not found at {url}; "
                f"available: {[c.name for c in comps]}"
            )
        return comps[index]

    def parse_components(self, html_text: str) -> list[LivewireComponent]:
        """Pull every ``wire:id`` / ``wire:snapshot`` pair out of a page."""
        out: list[LivewireComponent] = []
        # wire:snapshot and wire:id appear on the same root element; capture the
        # snapshot and the nearest id. We scan snapshot occurrences and read the
        # component name from the decoded JSON memo.
        for m in re.finditer(r'wire:snapshot="([^"]*)"', html_text):
            raw = html.unescape(m.group(1))
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            memo = obj.get("memo", {})
            name = memo.get("name", "")
            wire_id = memo.get("id", "")
            out.append(LivewireComponent(self, wire_id, raw, name))
        return out


def _strip_meta(value: Any) -> Any:
    """Recursively undo Livewire's ``[value, {"s":...}]`` dehydration tuples."""
    if isinstance(value, list) and len(value) == 2 and isinstance(value[1], dict) \
            and set(value[1].keys()) <= {"s", "class", "key", "e"}:
        return _strip_meta(value[0])
    if isinstance(value, dict):
        return {k: _strip_meta(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_strip_meta(v) for v in value]
    return value


def rand(prefix: str = "") -> str:
    """Random suffix helper so every run creates independent state."""
    s = secrets.token_hex(4)
    return f"{prefix}{s}" if prefix else s
