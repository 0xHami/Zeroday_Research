# Extended gin harness (stage-10 conditional/primitive findings)

A second harness that links the **same** local gin source as the stage-00 default harness
(`go.mod` `replace github.com/gin-gonic/gin => /src/gin`, gin supplied as the `ginsrc` build
context so `targets/gin` stays pristine). It starts several `gin.Engine` instances, each configured
the way a real consuming application would be, to give dynamic validation a live surface for the
findings that are **conditional** (behind an `Engine` toggle) or realized only through an **app
pattern**. The app code here is deliberately the minimal ordinary usage each finding describes —
the vulnerability is in gin, not in this scaffolding.

## Engines / ports (container → host; block 36274-36283)

| host | container | engine | config | serves findings |
|------|-----------|--------|--------|-----------------|
| 36275 | 8090 | demo | default config | VULN-004 `/account`, VULN-010 `/scheme`, VULN-011 `/jsonp`, VULN-019 `/fmt`, VULN-020 `/bindcontinue`, VULN-007-write `/save`, static `/static` |
| 36276 | 8091 | tp | `TrustedPlatform=X-CF-Connecting-IP` + a correct `SetTrustedProxies([192.0.2.0/24])` | VULN-003 `/ip` |
| 36277 | 8092 | rawpath | `UseRawPath=true, UnescapePathValues=true` | VULN-008 `/echo/:name`, `/read/:name`, `/files/:name` |
| 36278 | 8093 | slash | `RemoveExtraSlash=true` + literal-path guard middleware | VULN-009 `/admin/panel` |
| 36279 | 8094 | fixed | `RedirectFixedPath=true` | VULN-016 `/admin/secret` |
| 36280 | 8095 | mna | `HandleMethodNotAllowed=true` | VULN-017 `/internal/purge`,`/internal/item` |
| 36281 | 8096 | h2c | `UseH2C=true` | VULN-006 `/`, `/internal/admin` |
| 36282 | 8097 | rparam | root-level `/:tenant` route | VULN-001 escalation (fully attacker-chosen redirect host) |

## Build / run / stop

```bash
cd claude_audit/gin/exploits/_extharness
docker compose -p cvehunterlab_gin_ext up -d --build      # build + start (separate project, prefix-matched for cleanup)
docker compose -p cvehunterlab_gin_ext logs -f ext        # logs
docker compose -p cvehunterlab_gin_ext down -v            # stop + remove
```

Separate compose **project** (`cvehunterlab_gin_ext`) so it does not reconcile with the default
lab's `app` service; the `cvehunterlab_gin*` prefix keeps it visible to lab cleanup. Resource split:
`mem_limit 2g`, `cpus 2.0` (alongside the default app's 8g, within the 16g per-target budget).

Files: `main.go` (all engines), `go.mod` (replace → local gin), `Dockerfile` (two-stage build,
debian-slim runtime, uid 10002), `docker-compose.yml`.
