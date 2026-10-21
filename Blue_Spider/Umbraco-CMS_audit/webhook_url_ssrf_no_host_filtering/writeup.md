# VULN-006 — Server-Side Request Forgery via unvalidated webhook target URL

| | |
|---|---|
| **ID** | VULN-006 |
| **Software** | Umbraco CMS |
| **Repository** | https://github.com/umbraco/Umbraco-CMS |
| **Affected version** | 18.3.0-rc (commit-pinned; no tagged release) |
| **Commit** | `cee7d8981ab0fd18b4dc96449ae071edf1aaf21e` |
| **Severity** | Medium — CVSS 3.1 `6.5` (`AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:N`); **High ~`8.5`** (C:H) when `Hosting:Debug=true` exposes response bodies |
| **Status** | **CONFIRMED (dynamic, out-of-band)** |
| **Auth required** | A backoffice user with the **Settings** section (`TreeAccessWebhooks`) — admin by default, delegable to a non-admin Settings group (demonstrated here with a provisioned non-admin Settings user) |
| **Attacker gains** | The server originates HTTP requests to attacker-chosen internal/loopback/cloud-metadata targets, with attacker headers, following redirects; a blind port/host oracle by default, and a full internal-response read (IMDS credential theft) when Debug is on |

## Summary

Umbraco webhooks let a Settings-section user register a target URL that the server later `POST`s to when a
subscribed event fires. The only validation on save is that at least one event is selected — **the URL's
scheme, host and IP are never checked**, there is no allow-list, and the firing HTTP client leaves
`AllowAutoRedirect` at its default `true`. A Settings-tier user therefore turns the Umbraco server into an
SSRF proxy: it will connect to `http://169.254.169.254/…` (cloud metadata), `http://127.0.0.1:…` /
`http://<internal-host>:…` (internal services), or any address the operator never intended, sending
attacker-chosen headers. The webhook log leaks `statusCode`/`isSuccessStatusCode`/exception for a blind
port/host oracle even without debug mode; with `Umbraco:CMS:Hosting:Debug=true` it returns the full response
body and headers — a direct read of internal-only content and instance-metadata credentials.

Dynamically confirmed out-of-band: a webhook registered by a **non-admin Settings user** pointing at a host
listener made the app **container (172.18.0.2) connect out** to our address carrying our `X-Canary`/`X-Attacker`
headers, and — with Debug on — the webhook log returned our listener's full response body
(`{"oob":"canary-hit","secret":"internal-service-only"}`).

## How it works (mechanism & code trace)

**The (non-)validation.** `CreateAsync`/`UpdateAsync` call one validator, which looks only at the event count:

```csharp
// src/Umbraco.Core/Services/WebhookService.cs:37-45
private WebhookOperationStatus ValidateWebhook(IWebhook webhook)
{
    if (webhook.Events.Length <= 0) { return WebhookOperationStatus.NoEvents; }
    return WebhookOperationStatus.Success;   // the URL is never inspected
}
```

The request model marks the URL only `[Required]` (`ViewModels/Webhook/WebhookModelBase.cs:28-29`); no
FluentValidator for the webhook URL exists anywhere in the tree.

**The sink — firing to the raw URL with attacker headers.** The background job posts to the stored URL and
copies the webhook's attacker-controlled headers verbatim:

```csharp
// src/Umbraco.Infrastructure/BackgroundJobs/Jobs/DistributedJobs/WebhookFiring.cs:112-137
using HttpClient httpClient = _httpClientFactory.CreateClient(Constants.HttpClients.WebhookFiring);
using var request = new HttpRequestMessage(HttpMethod.Post, webhook.Url) { ... };   // :114 raw URL
...
foreach (KeyValuePair<string, string> header in webhook.Headers)                    // :128-131 attacker headers
    request.Headers.Add(header.Key, header.Value);
...
response = await httpClient.SendAsync(request, cancellationToken);                   // :137
```

**Auto-redirect is on.** The named client sets only a User-Agent and does **not**
`ConfigurePrimaryHttpMessageHandler`, so `HttpClientHandler.AllowAutoRedirect` stays `true` — a 302 to an
internal/metadata host is followed and not re-validated. The adjacent `IgnoreCertificateErrors` client *does*
configure a handler, confirming the omission is not an oversight of the pattern:

```csharp
// src/Umbraco.Web.Common/DependencyInjection/UmbracoBuilderExtensions.cs:257-261
builder.Services.AddHttpClient(Constants.HttpClients.WebhookFiring, (services, client) =>
{
    var productVersion = ...;
    client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue(..., productVersion));
});   // no ConfigurePrimaryHttpMessageHandler => AllowAutoRedirect defaults to true
```

**The oracle / full read.** `WebhookPresentationFactory` returns response body + headers only in
`IsDebugMode`; status/success/exception are always present. So even without debug you get a blind port/host
oracle; with `Hosting:Debug=true` (this lab, and any dev/staging) you read the whole internal response.

**Enabled by default, fast.** `WebhookSettings.Enabled = true` and `Period = 00:00:10`
(`Configuration/Models/WebhookSettings.cs`), so a subscribed event (e.g. `Umbraco.ContentPublish`) fires the
request within ~10s.

## Why it is a vulnerability (reasoning)

SSRF is exactly "an authenticated feature lets the attacker choose a URL the *server* will fetch, with no
egress allow-list." Every ingredient is present and unguarded: the destination is fully attacker-controlled
(no scheme/host/IP filtering), the request carries attacker headers, redirects are followed, and the response
is observable (blind oracle always; full body with debug). The Settings section is developer-tier, but the
sharp edges are (a) a **delegated non-admin** Settings group — proven here by provisioning a Settings-only
user that successfully registered the webhook — and (b) reaching **cloud instance metadata / internal-only
services** from the server's network position, which the attacker's own machine cannot reach. It is not
by-design: the fix for the earlier CVE deliberately hid the response body behind debug mode but added no
network controls, so the request-forgery primitive itself remains.

## Reproduction

`cd exploits/VULN-006 && ./run.sh` (env: `BASE_URL`, `ADMIN_USER`, `ADMIN_PASS`, optional `DOCKER_GATEWAY`).

1. **Preconditions:** admin provisions a non-admin Settings-only group + user; the exploit starts an OOB HTTP
   listener on `0.0.0.0:<rnd>` (container-reachable at `http://172.18.0.1:<port>/…`) and creates a document.
2. **Register (as the Settings user):** `POST /webhook` with an internal target URL and a custom header →
   **201 Created** — an internal/loopback URL is accepted with no validation.
3. **Trigger:** `PUT /document/{id}/publish` → raises `Umbraco.ContentPublish`.
4. **Proof (SSRF):** within ~10s the listener records:
   ```
   POST /canary-<rnd>  from 172.18.0.2  UA=Umbraco-Cms/18.3.0-rc.preview.34
   X-Canary: <rnd>   X-Attacker: ssrf     body={"id":"<doc-guid>","cultures":[]}
   ```
   The server itself connected out to our attacker-chosen host with our headers.
5. **Proof (oracle + full read):** `GET /webhook/logs` →
   ```
   open  target http://172.18.0.1:<port>/…  -> statusCode "OK (200)", responseBody
         {"oob":"canary-hit","secret":"internal-service-only"}     # Debug=true leaks the internal response
   closed target http://172.18.0.1:<closed>/… -> statusCode "ConnectionError", exceptionOccured=true
   ```
   Open vs closed differ ⇒ internal port scanner; the leaked body is the IMDS/secret-read primitive.

Ends with `[OK]`/`==> VULN-006: CONFIRMED`. Full capture: `run.log`, `request.http`, `response.txt`,
`evidence/oob_listener.log`, `evidence/webhook_logs.json`.

## Impact

- **Confidentiality (blind, C:L → full, C:H with Debug):** map internal hosts/ports; reach services bound to
  the app's network (databases, admin panels, other containers); read cloud instance metadata
  (`169.254.169.254`) — which on AWS/GCP/Azure yields **IAM/role credentials** — when Debug exposes bodies.
  `Hosting:Debug=true` is the default in development/staging and is what this lab runs.
- **Scope change (S:C):** the request originates from the server into a different security zone the client
  cannot otherwise reach.
- **Chaining:** SSRF → IMDS credential theft → cloud account pivot is the canonical chain. Because Settings is
  also RCE-capable via **VULN-001** (template/settings code execution), the most valuable *isolated* use of
  this bug is a delegated non-admin Settings operator, or reaching a metadata endpoint from a box where the
  app has no such capability of its own.

## Suggested fix

- Validate the URL **scheme + host on save** (reject non-http(s); reject credentials in the URL).
- **Resolve the host and block** loopback / private (RFC1918) / link-local (169.254/16, incl. IMDS) /
  ULA / multicast ranges; **re-resolve at each fire** to defeat DNS-rebinding.
- Set `AllowAutoRedirect = false` on the WebhookFiring client (or re-validate the post-redirect destination
  against the same rules).
- Offer an operator **allow-list** of permitted webhook hosts; keep the response body behind debug (already
  done) *and* behind the network controls above.

## References
- **CVE-2024-29035 / GHSA-74p6-39f2-23v3** — "Umbraco Blind SSRF & (indirectly) Port Scan by using Webhooks"
  (affected 13.0.0–13.1.1). The 13.1.1 remediation only moved the response body behind debug mode and added no
  IP/host filtering — source-confirmed still the case at 18.3.0-rc, hence this remains exploitable.
- OWASP — Server-Side Request Forgery Prevention Cheat Sheet.
- PortSwigger Web Security Academy — SSRF (blind SSRF, out-of-band detection, cloud metadata).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 25 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `Umbraco webhook SSRF internal IP metadata "AllowAutoRedirect" OR "169.254.169.254" webhook URL validation 2025 2026` (WebSearch) — search budget exhausted before this query ran; no result returned.
2. GitHub advisory DB, full listing for NuGet `Umbraco.Cms` (gh GraphQL `securityVulnerabilities`) — only webhook-related entries: GHSA-74p6-39f2-23v3 / CVE-2024-29035 (blind SSRF + port scan via webhooks, 13.x) and GHSA-4gp9-ff99-j6vj / CVE-2024-48925 (low-privilege access to the webhook API, 14.3.0). No advisory for 14+/17/18 webhook URL validation.
3. WebFetch `github.com/advisories/GHSA-74p6-39f2-23v3` and the fix commit `umbraco/Umbraco-CMS@6b80678` — the 13.1.1 fix only changed `WebhookMapDefinition` to hide exception/response/status details outside debug mode; it added no scheme/host/IP validation and no redirect handling.
4. `gh api repos/umbraco/Umbraco-CMS/commits?path=src/Umbraco.Core/Services/WebhookService.cs` and `.../WebhookFiring.cs` (since 2026-06) — no commits; no upstream hardening after the audited commit.
5. Umbraco Aug-18-2026 and Oct-6-2026 security advisories (WebFetch) — no webhook item.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2024-29035 / GHSA-74p6-39f2-23v3 — same component (webhook target URL) and same primitive (blind SSRF / port scan). The vendor fix for 13.1.1 only hid log details outside debug mode; it did not add host filtering, and this writeup documents that the v14+ Management API presentation layer still always exposes status/exception (i.e. the mitigation did not carry over) plus auto-redirect following and IMDS reach. Treat this finding as "incomplete fix / regression of a public CVE" rather than a new class.
- CVE-2024-48925 / GHSA-4gp9-ff99-j6vj — authorization of the webhook API for low-privilege users (14.3.0); different root cause.

**Reasoning:** The SSRF-via-webhook-URL primitive in this exact component is publicly known (CVE-2024-29035), which is why confidence is low. What is not publicly described is that the current Management API still surfaces status/exception without debug mode (undoing the only mitigation the vendor shipped), that redirects are followed, and that no host/IP allow-list exists in 17.x/18.x. A vendor may regard outbound webhooks to arbitrary hosts as by-design; the strongest disclosable angle is the incomplete-fix/regression of the log-detail mitigation.
