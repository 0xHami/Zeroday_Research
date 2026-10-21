"""
Resilience shim for the Umbraco-CMS stage-10 exploits.

The lab is shared: several stage-10 agents authenticate as the SAME admin
concurrently, and Umbraco's reference-token model means a sibling's fresh
login can rotate/revoke the token this process is holding — surfacing as a
sporadic HTTP 401 (or a read timeout when the box is briefly saturated) on a
call that worked seconds earlier.

`RClient` is a drop-in `_common.ApiClient` that transparently re-authenticates
(cookie login -> PKCE bearer) and retries on 401 / transient network errors, so
an exploit's verdict reflects the *vulnerability*, not shared-lab token churn.
`resilient_admin_client()` / `login()` also retry the initial login through a
transient account-lockout window.
"""
import time

import requests

import _common as c


class RClient(c.ApiClient):
    def __init__(self, username, password, label=""):
        self._pw = password
        super().__init__(username, password, label)

    def _reauth(self):
        self.session = c.cookie_login(self.username, self._pw)
        self.token = c.get_bearer(self.session)
        self.session.headers["Authorization"] = f"Bearer {self.token}"

    def req(self, method, path, **kw):
        # NB: _common.ApiClient.req already passes timeout=30; don't set it here (would collide).
        last = None
        for attempt in range(6):
            try:
                r = super().req(method, path, **kw)
            except requests.exceptions.RequestException as e:
                last = e
                if attempt == 5:
                    raise
                time.sleep(3)
                try:
                    self._reauth()
                except Exception:
                    pass
                continue
            if r.status_code == 401 and attempt < 5:
                time.sleep(2)
                try:
                    self._reauth()
                except Exception:
                    pass
                continue
            return r
        if last:
            raise last
        return r


def login(username, password, label="", tries=8):
    """Construct an RClient, retrying through transient lockout / timeout windows."""
    last = None
    for i in range(tries):
        try:
            return RClient(username, password, label)
        except Exception as e:
            last = e
            time.sleep(5)
    raise last


def resilient_admin_client():
    return login(c.ADMIN_USER, c.ADMIN_PASS, "admin")
