# rocket.chat: target manifest

## Runtime

### Target identity
- **Name:** Rocket.Chat
- **Repository:** https://github.com/rocketchat/rocket.chat
- **Version:** `9.1.0-develop` (`package.json:3` and `apps/meteor/package.json:3`; `git describe --tags --always` gives `9f3d6c8` and the checkout is on branch `develop`, so: commit-pinned, no tagged release)
- **Commit:** `9f3d6c8c48911e32ed6c2ce36befd431faa71190`

The running lab was checked against that commit rather than assumed to match it:
the image carries `"gitCommitHash": "9f3d6c8c48911e32ed6c2ce36befd431faa71190"`
in `/app/bundle/star.json`, and the live workspace reports
`info.commit.hash = 9f3d6c8c48911e32ed6c2ce36befd431faa71190`,
`info.commit.branch = develop` at `GET /api/info`.

### Product & type
**Type: Standalone web app.** Rocket.Chat is a self-hosted team-communication
platform (chat, channels, teams, omnichannel, apps). It runs on its own and the
lab runs it as the vendor documents: the app behind Traefik, with MongoDB and
NATS. No third-party extensions or marketplace apps were installed: the
workspace has no internet access and the first-party surface is already large.

### Host platform
None. The app is the target. Its own runtime dependencies are MongoDB 8.2.12
(single-node replica set `rs0`) and NATS 2.11 as the monolith transporter, both
started by `audit/rocket.chat/setup/docker-compose.yml`.

### Install source
- The target's own `docker-compose-ci.yml` (the MongoDB replica-set entrypoint and the Traefik-in-front topology are taken from it) and `apps/meteor/.docker/Dockerfile.alpine` (how the release image is built).
- https://docs.rocket.chat/docs/deploy-with-docker-docker-compose - the documented Compose deployment.
- https://github.com/RocketChat/rocketchat-compose - the vendor's deployment compose files (`compose.yml`, `compose.database.yml`, `compose.nats.yml`, `compose.traefik.yml`, `.env.example`), which this lab follows for the app, database, transporter and proxy.
- https://docs.rocket.chat/docs/manage-settings-using-environmental-variables - the `OVERWRITE_SETTING_<id>` mechanism used for the three lab settings.
- https://docs.rocket.chat/docs/deployment-environment-variables - `ROOT_URL`, `PORT`, `MONGO_URL`, `ADMIN_*`.
- https://docs.rocket.chat/docs/system-requirements - MongoDB 8.0+, Node 24.15+, 4 GiB for a small deployment.

The app is **not built from source** in the lab: it runs
`rocketchat/rocket.chat:sha-9f3d6c8`, the vendor's own release image published
by Rocket.Chat CI from the audited commit
(digest `sha256:e2464599fe2279b4985c458e4b96d24e9db75bead6d7bfe972ca7dc9893f0019`).
A Meteor production build of this monorepo needs far more RAM and disk than the
target's whole budget, and the vendor publishes a per-commit image exactly so
the shipped artifact can be run. See `### Known issues / workarounds`.

### Stack
- **Language/runtime:** TypeScript / JavaScript on Node.js v24.22.1 (the image's node; the bundle was built with 24.15.0).
- **Framework:** Meteor 3.5.2 (`apps/meteor/.meteor/release`), React 18 client, Moleculer service broker, Express plus the in-house `@rocket.chat/http-router` (Hono) for HTTP.
- **App server:** the Meteor bundle, `node main.js`, listening on 3000 inside the container.
- **Database:** MongoDB 8.2.12 (wiredTiger), single-node replica set `rs0`, no authentication, internal network only.
- **Other services:** NATS 2.11 (`monolith+nats://nats:4222`) as the Moleculer transporter; Traefik v3.4 as the documented reverse proxy; Mailpit v1.31.4 as the lab's mail sink.
- **Assets/build:** prebuilt Meteor bundle inside the vendor image (client bundle plus server), `NODE_ENV=production`.
- **Notable libraries wired in:** `@rocket.chat/server-fetch` (SSRF-checked outbound HTTP), `isolated-vm` (integration scripts), `nodemailer`, `swagger-ui-express` (`/api-docs`), the Apps-Engine, `@rocket.chat/license` (premium gating and the air-gap restriction).

### Compose project name
`bluespiderlab_rocket.chat`

That is the name the lab is **identified by**: every container, network and
volume is named `bluespiderlab_rocket.chat_*`, and the published container
carries the label `com.docker.compose.project=bluespiderlab_rocket.chat`, which
is what Blue Spider reads to find, check and destroy a lab (verified:
`labs.running()` is true, `labcheck.lab_problems()` is empty, and
`attacker.plan()` resolves this lab's two networks and the
`39649=bluespiderlab_rocket.chat_proxy:80` forward).

Docker Compose v5 **refuses a project name containing a dot**
(`invalid project name "bluespiderlab_rocket.chat"`), so the `docker compose`
commands below run under `-p bluespiderlab_rocket_chat` and the one published
container is started with `docker run` carrying the label above. A
service-level label cannot substitute: Compose overwrites its own labels
(tested). See `### Known issues / workarounds`.

### How to start
```bash
BLUESPIDER_PORT_BASE=39649 audit/rocket.chat/setup/rebuild.sh
```

`rebuild.sh` is the one procedure: it clears this target's leftovers, starts the
application stack, waits for the app's healthcheck, confirms the workspace is
not air-gap restricted and then detaches the app from the only network with a
route off the host, starts Traefik on the published port, waits for `/`, and
seeds the workspace. About 3 minutes on a warm image cache. The individual
steps, if they are ever needed one at a time:

```bash
export LAB_PORT=39649
docker compose -p bluespiderlab_rocket_chat \
  -f audit/rocket.chat/setup/docker-compose.yml \
  -f audit/rocket.chat/setup/mailpit.yml up -d
docker network disconnect bluespiderlab_rocket.chat_edge bluespiderlab_rocket.chat_app
docker run -d --name bluespiderlab_rocket.chat_proxy \
  --label com.docker.compose.project=bluespiderlab_rocket.chat \
  --memory 192m --cpus 0.2 --network bluespiderlab_rocket.chat_edge \
  -p 127.0.0.1:39649:80 \
  -v "$PWD/audit/rocket.chat/setup/traefik/dynamic.yml:/etc/traefik/dynamic.yml:ro" \
  traefik:v3.4 --providers.docker=false \
  --providers.file.filename=/etc/traefik/dynamic.yml --entrypoints.http.address=:80
docker network connect bluespiderlab_rocket.chat_lab bluespiderlab_rocket.chat_proxy
```

### How to stop
```bash
docker compose -p bluespiderlab_rocket_chat \
  -f audit/rocket.chat/setup/docker-compose.yml \
  -f audit/rocket.chat/setup/mailpit.yml down -v --remove-orphans
docker rm -f bluespiderlab_rocket.chat_proxy
docker network rm bluespiderlab_rocket.chat_edge
```

### How to rebuild
The running lab is destroyed when the scan ends; everything needed to bring it
back is preserved in `audit/rocket.chat/setup/`:
`docker-compose.yml` (the application stack and both networks), `mailpit.yml`
(the mail sink, from `deploy/lab-services/`), `traefik/dynamic.yml` (the proxy's
file-provider config), `scripts/seed.js` (the workspace seed), `rebuild.sh`
(the procedure) and `README.md` (ports, credentials, every manual fix and why).
Nothing is built from a Dockerfile; the images are pulled.

```bash
BLUESPIDER_PORT_BASE=39649 audit/rocket.chat/setup/rebuild.sh
```

### Base URL
`http://127.0.0.1:39649`

Same address inside the attacker container from stage 11 on: the console
forwards the published port (`39649=bluespiderlab_rocket.chat_proxy:80`). From
inside the lab's own network the app is also `http://rocketchat:3000` and the
proxy `http://bluespiderlab_rocket.chat_proxy:80` (both verified).

### Exposed ports & resource split
Per-target budget (from `run_prompts/rocket.chat/resources.json` / env): **4 GB RAM, 3.0 CPU, 15 GB disk**, split across 5 services:

| Service | Container | Host port -> container | mem_limit | cpus | Notes |
|---------|-----------|------------------------|-----------|------|-------|
| proxy (Traefik) | `bluespiderlab_rocket.chat_proxy` | `127.0.0.1:39649` -> `80` | 192m | 0.2 | the only published port; the only container with a route off the host |
| app (Rocket.Chat) | `bluespiderlab_rocket.chat_app` | not published (internal network) | 2304m | 1.7 | the target; V8 heap limit 1344 MB at this cap |
| db (MongoDB) | `bluespiderlab_rocket.chat_db` | not published (internal network) | 1216m | 0.9 | replica set `rs0` |
| nats | `bluespiderlab_rocket.chat_nats` | not published (internal network) | 128m | 0.1 | monolith transporter |
| mail (Mailpit) | `bluespiderlab_rocket.chat_mail` | not published (internal network) | 128m | 0.1 | side service |
| **Totals** | | | **3968m / 4096m** | **3.0 / 3.0** | |

- **RAM / CPU:** within budget, no escape hatch needed; read back from `docker inspect` rather than from the compose file. The app gets the largest share because the Meteor server is the heavy process.
- **Disk:** `storage_opt` is **not enforceable on this host** and was skipped per CLAUDE.md: Docker accepts `--storage-opt size=100M`, but with the containerd overlayfs snapshotter under gVisor the quota is not applied (a 300 MB file was written inside a 100 MB cap). Actual usage is modest: about 3.4 GB of images (app 1.62 GB, MongoDB 1.38 GB, Traefik 289 MB, NATS 40 MB, Mailpit 60 MB) and about 222 MB of volumes, so roughly 3.6 GB of the 15 GB budget.
- **Networks:** `bluespiderlab_rocket.chat_lab` is `internal: true` and carries the app, database, NATS, mail sink and the proxy's back end; `bluespiderlab_rocket.chat_edge` is the only network with a route off the host and holds the proxy alone. The app was attached to `edge` for its first boot only (see `### Known issues / workarounds`) and is now on `lab` alone: outbound DNS and HTTP from the app both fail (verified: `EAI_AGAIN`), while `http://mailpit:8025` from the app answers 200. Nothing publishes on `0.0.0.0`, nothing uses host networking, and no container is privileged or has an added capability.

### Credentials
| Role | Tenant / org | Username | Password | Notes |
|------|--------------|----------|----------|-------|
| workspace admin | - | `admin` | `Bspdr-Lab-Adm1n!` | created on first boot from `ADMIN_*`; email `admin@lab.invalid`, unverified |
| team owner | team `acme` | `acme.owner` | `Acme-0wner-Lab!` | owns the `acme` team and `acme-private` |
| ordinary user | team `acme` | `alice` | `Al1ce-Lab-Pass!` | member of `acme` and `acme-private` |
| team owner | team `globex` | `globex.owner` | `Glob3x-0wner-Lab!` | owns the `globex` team and `globex-private` |
| ordinary user | team `globex` | `bob` | `B0b-Lab-Password!` | member of `globex` and `globex-private` |
| ordinary user | none | `carol` | `Car0l-Lab-Pass!` | in no team: the second ordinary user for horizontal tests |

Rocket.Chat's tenancy unit is the **team** (one workspace, many teams), so the
two teams above are the two tenants: each has its own owner, its own ordinary
member and its own private channel holding a seeded secret message, which is
what a cross-tenant read must not reach.

- **Database:** MongoDB `rocketchat`, no authentication, reachable only on the lab's internal network at `mongodb://mongodb:27017/rocketchat?replicaSet=rs0` (how the vendor's own compose ships it, `ALLOW_EMPTY_PASSWORD=yes`). Read it with `docker exec -i bluespiderlab_rocket.chat_db mongosh --quiet rocketchat --eval '<js>'`.
- **Secrets:** none were injected. No licence is installed (Community edition), the workspace is **not** registered with Rocket.Chat Cloud, and every password above was generated for this lab and satisfies the product's shipped policy (14+ characters, upper, lower, digit, symbol). A password-reset or invitation token is read from the mail sink: `curl http://mailpit:8025/api/v1/messages` from inside the lab (verified end to end: a reset mail for `alice@lab.invalid` arrived carrying `http://127.0.0.1:39649/reset-password/<token>`). A personal access token can be minted at `POST /api/v1/users.generatePersonalAccessToken`.

### Side services
| Service | Compose file | Reached at (inside the lab) | How the app was pointed at it | How to read it |
|---------|--------------|-----------------------------|-------------------------------|----------------|
| mailpit | `setup/mailpit.yml` | `mailpit:1025` (SMTP, no auth, no TLS) | `OVERWRITE_SETTING_SMTP_Host=mailpit`, `OVERWRITE_SETTING_SMTP_Port=1025`, `OVERWRITE_SETTING_From_Email=rocketchat@lab.invalid` | `http://mailpit:8025/api/v1/messages`, and `/api/v1/message/<id>` for the body with its links |

`oidc.yml` and `s3.yml` were **not** added, and why is recorded under
`## Security configuration` -> `Not done`.

### Target's own surface
Rocket.Chat is the whole application, so this is its top-level surface; stage 02
takes it apart properly. The live workspace serves its own OpenAPI 3.1 document
at `GET /api/docs/json` (**493 documented paths**, unauthenticated) with Swagger
UI at `/api-docs/`: start there, it is the authoritative route inventory for
this exact build.

| Route or entry point | Auth | What it does | Code under `targets/rocket.chat/` |
|----------------------|------|--------------|-----------------------------------|
| `/` and the SPA routes (`/home`, `/channel/:name`, `/admin/*`, `/account/*`, `/directory`, `/search`) | session (some public) | the React web client | `apps/meteor/client/startup/routes.tsx` |
| `/api/v1/*` (44 modules: `chat`, `rooms`, `channels`, `groups`, `im`, `users`, `teams`, `settings`, `uploads`, `integrations`, `oauthapps`, `e2e`, `moderation`, `invites`, `import`, `permissions`, `roles`, `subscriptions`, `videoConference`, `ai-search`, ...) | token (`X-Auth-Token` + `X-User-Id`), some anonymous | the REST API | `apps/meteor/server/api/v1/`, plus `apps/meteor/ee/server/api/v1/` (premium) |
| `/api/docs/json`, `/api-docs/` | none | the OpenAPI document and Swagger UI | `apps/meteor/server/api/default/openApi.ts` |
| `/api/info` | none (more fields when authenticated) | version, and the commit when authenticated | `apps/meteor/server/api/default/info.ts` |
| `/websocket`, `/sockjs/*` | session over DDP | the realtime (DDP) transport: Meteor methods and subscriptions, a surface the REST API does not cover | `packages/ddp-server/`, `apps/meteor/server/meteor-methods/` |
| `/hooks/*` | per-integration token in the URL | incoming webhook integrations; scripts run in `isolated-vm` | `apps/meteor/server/lib/integrations/`, `apps/meteor/app/integrations/` |
| `/oauth/authorize`, `/oauth/token`, `/oauth/userinfo`, `/oauth/register`, `/.well-known/oauth-authorization-server` | mixed | Rocket.Chat acting as an OAuth2 **provider** | `apps/meteor/server/lib/auth/oauth2-server/` |
| `/file-upload/*`, `/avatar/*` | session (`FileUpload_ProtectFiles` on) | uploaded files and avatars; GridFS store | `apps/meteor/server/lib/media/file-upload/`, `apps/meteor/app/file-upload/` |
| `/api/apps/*`, `/api/apps/public/:appId`, `/api/apps/private/:appId/:hash` | mixed | the Apps-Engine: installed apps' own HTTP endpoints | `apps/meteor/server/modules/apps/`, `apps/meteor/ee/server/apps/` |
| `/livechat/*`, `/api/v1/livechat/*` | anonymous visitor | Omnichannel / Livechat (**disabled by default** in 9.x: `Livechat_enabled=false`) | `apps/meteor/app/livechat/`, `apps/meteor/server/api/v1/omnichannel/` |
| `/reset-password/:token`, `/invite/:hash`, `/register/:hash`, `/login-token/:token`, `/2fa/:method/:challengeId`, `/saml/:token` | anonymous | the account flows that arrive by link | `apps/meteor/client/startup/routes.tsx`, `apps/meteor/server/lib/auth/` |

Defaults in force that findings are judged against (read back live, see
`## Security configuration`): 2FA on with the password fallback, password policy
on at 14 characters, failed-login blocking by IP and by user, the API rate
limiter on, CSP on, `X-Frame-Options: sameorigin`, CORS off, protected file
uploads on, public registration, email verification off, E2E encryption off,
Omnichannel off, and the Community (unlicensed) edition, so every premium module
is gated off.

### Key endpoints found during smoke test
| Method | Path | Status | Notes |
|--------|------|--------|-------|
| GET | `/` | 200 | the SPA shell; CSP, `X-Frame-Options: sameorigin`, `X-Content-Type-Options: nosniff` present |
| GET | `/health` | 200 | `{"status":"ok"}` |
| GET | `/api/info` | 200 | `version 9.1`, and the audited commit hash when authenticated |
| GET | `/api/docs/json` | 200 | the OpenAPI 3.1 document, 493 paths, no authentication |
| POST | `/api/v1/login` | 200 | returns `authToken` + `userId` for `admin` |
| GET | `/api/v1/users.list?count=10` | 200 | authenticated; 7 users (6 seeded plus `rocket.cat`) |
| GET | `/api/v1/teams.listAll?count=10` | 200 | authenticated; the two seeded teams `acme` and `globex` |
| POST | `/api/v1/chat.postMessage` | 200 | messaging works (this is the call an air-gap restricted workspace refuses) |
| GET | `/sockjs/info` | 200 | the DDP transport is live |
| GET | `/.well-known/oauth-authorization-server` | 200 | the OAuth2 provider metadata |

Secure-baseline headers seen live on `/`:
`Content-Security-Policy: default-src 'self' https://cdn.zapier.com; connect-src *; ... script-src 'self' 'unsafe-eval' <two sha256 hashes> https://cdn.zapier.com https://zapier.com; style-src 'self' 'unsafe-inline' ...`,
`X-Frame-Options: sameorigin`, `X-Content-Type-Options: nosniff`,
`X-XSS-Protection: 1`, `Access-Control-Allow-Origin: *`, `X-Powered-By: Express`.

### Container names
- `bluespiderlab_rocket.chat_app` - the target (`rocketchat/rocket.chat:sha-9f3d6c8`), port 3000 inside the lab, alias `rocketchat`.
- `bluespiderlab_rocket.chat_db` - MongoDB 8.2.12, alias `mongodb`.
- `bluespiderlab_rocket.chat_nats` - NATS 2.11, alias `nats`.
- `bluespiderlab_rocket.chat_mail` - Mailpit, alias `mailpit`.
- `bluespiderlab_rocket.chat_proxy` - Traefik v3.4, the only published port, started with `docker run`.
- Networks: `bluespiderlab_rocket.chat_lab` (`internal: true`), `bluespiderlab_rocket.chat_edge`.
- Volumes: `bluespiderlab_rocket.chat_mongodata`, `bluespiderlab_rocket.chat_uploads`.

Because the stack's Compose project is `bluespiderlab_rocket_chat` (no dot
allowed), use `docker exec` by container name rather than `compose exec`:

```bash
docker exec -i bluespiderlab_rocket.chat_app node -e 'console.log(process.version)'
docker exec -i bluespiderlab_rocket.chat_db mongosh --quiet rocketchat --eval 'db.users.countDocuments()'
```

### Known issues / workarounds
- **No file under `targets/rocket.chat/` was created, edited or deleted.** The lab is configuration only; every file this stage wrote is under `audit/rocket.chat/`. No security control, filter or check in the target's source was touched.
- **The app runs the vendor's release image for the audited commit, not a source build.** `rocketchat/rocket.chat:sha-9f3d6c8`, verified to carry commit `9f3d6c8c4891...` both in the image (`star.json`) and at runtime (`/api/info`). A Meteor production build of this monorepo exceeds the target's whole 4 GB / 15 GB budget. Consequence for later stages: the running bytes correspond to `targets/rocket.chat/` at this commit, but they are the **production bundle**, so `NODE_ENV=production`, no source maps for third-party server deps, and no dev-only code paths.
- **Compose project name.** Compose v5 rejects `bluespiderlab_rocket.chat` (a dot is not allowed in a project name), so the stack runs under `-p bluespiderlab_rocket_chat` while every object is named `bluespiderlab_rocket.chat_*` and the published proxy carries `com.docker.compose.project=bluespiderlab_rocket.chat` as a `docker run` label. Overriding that label from a Compose service does not work: Compose rewrites its own labels (tested). Teardown by name therefore still finds everything.
- **The app reached the internet once, during its first boot, and is now sealed.** An unlicensed workspace that has never reached `https://collector.rocket.chat/` is air-gap restricted (`ee/packages/license/src/AirGappedRestriction.ts`), and a restricted workspace refuses `chat.sendMessage`, `chat.update`, `chat.postMessage`, `rooms.createDiscussion` and `rooms.mediaConfirm` with `restricted-workspace`. This was observed, not assumed: the first build of this lab had no egress and every seeded message failed that way. The product's own default (`Statistics_reporting`) makes that one call at startup and stores the signed token it returns, which buys a 10-day grace period (`Cloud_Workspace_AirGapped_Restrictions_Remaining_Days` is now `10`). `rebuild.sh` lets the first boot make the call, confirms messaging works, then detaches the `edge` network from the app. **This does not touch the code path of any finding**: it changes `AirGappedRestriction.restricted` from `true` to `false`, which is the state of every licensed or internet-connected production workspace, and it is the state in which the product's own features are reachable at all. Note for stage 11: the restriction is recomputed daily, so a lab left running for more than 10 days starts refusing those five endpoints again; `rebuild.sh` resets it.
- **`docker cp` into the app container does not reach `/tmp`.** Under gVisor, `/tmp` in the container is a tmpfs that shadows the path `docker cp` writes to, so the copied file is invisible to processes inside. Anything to run in the container is piped to its `node`/`sh` over stdin instead (`docker exec -i ... node < script.js`).
- **`ADMIN_USERNAME=admin` logs "Username provided already exists or is blocked from usage".** `admin` is on the product's blocked-username list, so `checkUsernameAvailability` rejects the environment variable; the account is still created as `admin`, because that is the hardcoded default in `insertAdminUserFromEnv` (`apps/meteor/server/startup/initialData.ts:23`). Cosmetic only.
- **The database healthcheck was rewritten, because the probe itself destabilised the lab.** A `mongosh` run costs about 140 MB and a CPU burst inside the database's cap; at the 2-second interval the lab was first built with, it held the container's whole 0.9 CPU share at idle and spiked memory enough for mongod to be killed once (the log reports a non-empty `mongod.lock` and an unclean restart). The check now verifies the replica set has a primary only until it does, then switches to a 0.15 s bash TCP probe via a marker file. Measured after the change: database CPU 12-35% of its share instead of a sustained 91%, memory flat at about 233 MB, no restarts. This matters beyond tidiness: a probe that perturbs the database every interval would add latency noise to any timing-sensitive finding in a later stage.
- **Per-container disk quotas are not enforced on this host** (containerd overlayfs snapshotter under gVisor): `--storage-opt size=100M` was accepted and a 300 MB write succeeded. Skipped, as CLAUDE.md allows, with image and volume sizes kept modest.
- **The setup wizard was not driven through the browser, because it cannot be completed in a lab.** Its last step (`packages/ui-setup-wizard/src/steps/RegisterServerStep.tsx`) offers only cloud registration or an offline registration token fetched by hand from Rocket.Chat Cloud; there is no skip. The workspace is therefore set up the documented headless way (`ADMIN_*` plus `OVERWRITE_SETTING_Show_Setup_Wizard=completed`), and `audit/rocket.chat/pw/install.py` proves in a real browser that this produced a working workspace (login lands on `/home`, not the wizard; screenshots in `audit/rocket.chat/pw/screenshots/`).
- **No `--cap-add`, no privileged container, no host networking, no host bind mount** beyond `audit/rocket.chat/setup/traefik/dynamic.yml` (read-only, into the proxy), which is the one path a lab container is allowed to mount from the audit tree.

## Security configuration

### Documentation followed
- `targets/rocket.chat/SECURITY.md` (the repository's own: it points at the handbook and the HackerOne VDP, and specifies no deployment hardening).
- https://docs.rocket.chat/docs/secure-rocketchat - the vendor's security guide (password policy, 2FA, SSO, E2EE, ABAC, device management, rate limiter, DLP, FIPS).
- https://docs.rocket.chat/docs/deploy-with-docker-docker-compose - the deployment guide (pin a version, HTTPS via Traefik and Let's Encrypt, DNS, object storage for uploads).
- https://docs.rocket.chat/docs/system-requirements - MongoDB 8.0+, Node 22.22.3+/24.15+, 4 GiB RAM for a small deployment.
- https://docs.rocket.chat/docs/manage-settings-using-environmental-variables - `OVERWRITE_SETTING_<id>`.

### Enabled
Rocket.Chat ships its security controls **on by default** and the guide's items
are per-workspace choices rather than switches an operator must flip, so almost
nothing needed enabling. What the lab set, and why:

- **A pinned version, not `latest`** (deploy guide: "For production environments, it's strongly recommended to specify a fixed version number"): the image is pinned to the audited commit, `rocketchat/rocket.chat:sha-9f3d6c8`. *Verified live:* `/api/info` reports `9.1.0-develop`, commit `9f3d6c8c4891...`.
- **MongoDB 8.2 as a replica set** (system requirements: "MongoDB 8.0 or later"; the app connects with `?replicaSet=rs0`). *Verified live:* the startup banner reports `MongoDB Version: 8.2.12`, `MongoDB Engine: wiredTiger`, with no version warning.
- **A reverse proxy in front of the app**, as both the deployment guide and the target's own `docker-compose-ci.yml` do. This also keeps `HTTP_FORWARDED_COUNT` at its shipped default of `1` (`apps/meteor/packages/rocketchat-mongo-config/server/index.js:38`) truthful: there is exactly one proxy, so the client IP the rate limiter and failed-login blocker see is the one Traefik sets, not a header the client chose. *Verified live:* `/` answers through Traefik on `127.0.0.1:39649`.
- **SMTP configured** (the product cannot send password resets, invitations or email 2FA codes with `SMTP_Host` empty, which is the shipped default): pointed at the lab's mail sink. *Verified live:* a password-reset mail for `alice@lab.invalid` arrived in Mailpit with a working `http://127.0.0.1:39649/reset-password/<token>` link.
- **A strong admin password** satisfying the product's own shipped policy (14 characters, upper, lower, digit, symbol).

### Left at default
Read back from the running workspace, not from the source. These are the
shipped values and the lab did not touch them:

| Setting | Value |
|---------|-------|
| `Accounts_TwoFactorAuthentication_Enabled` / `_By_Email_Enabled` / `_By_TOTP_Enabled` | `true` / `true` / `true` |
| `Accounts_TwoFactorAuthentication_Enforce_Password_Fallback` | `true` |
| `Accounts_Password_Policy_Enabled`, `_MinLength` | `true`, `14` |
| `Block_Multiple_Failed_Logins_Enabled` / `_By_Ip` / `_By_User` | `true` / `true` / `true` |
| `API_Enable_Rate_Limiter` | `true` |
| `Enable_CSP` | `true` |
| `Iframe_Restrict_Access`, `Iframe_X_Frame_Options` | `true`, `sameorigin` |
| `API_Enable_CORS` | `false` |
| `FileUpload_ProtectFiles`, `FileUpload_Storage_Type` | `true`, `GridFS` |
| `Accounts_RegistrationForm` | `Public` |
| `Accounts_EmailVerification`, `Accounts_ManuallyApproveNewUsers` | `false`, `false` |
| `Accounts_AllowAnonymousRead` | `false` |
| `Accounts_LoginExpiration` | `90` (days) |
| `E2E_Enable` | `false` |
| `Force_SSL` | `false` |
| `Livechat_enabled` | `false` (new in 9.x) |
| `Prometheus_Enabled` | `false` |

Several of those are off-by-default protections that the vendor's documentation
does **not** tell operators to enable (E2E encryption, email verification, manual
approval of new users, CORS, Prometheus). They were deliberately left off: that
is stage 05's territory, and an off-by-default weakness is a real finding worth
reporting as conditional. `TEST_MODE` is **not** set anywhere in the lab: it
disables the rate limiter (`apps/meteor/server/lib/RateLimiter.js:5`), swallows
outgoing mail and relaxes 2FA, and setting it would have hidden real bugs.

### Not done
- **HTTPS / Let's Encrypt.** The deployment guide wants `TRAEFIK_PROTOCOL=https` with `LETSENCRYPT_ENABLED=true`, which needs a real domain with a public A record and an ACME challenge the lab cannot answer. The lab uses the guide's own local-testing configuration (`ROOT_URL=http://localhost`, `LETSENCRYPT_ENABLED=false`, `TRAEFIK_PROTOCOL=http`), so `Force_SSL` stays at its default `false` and cookies are not `Secure`. Consequence to remember when judging findings: transport-security issues (missing HSTS, a cookie without `Secure`) are properties of this lab, not of the product.
- **The monitoring stack** (`compose.monitoring.yml`: Prometheus, Grafana, Loki, OpenTelemetry collector, node-exporter) and `OVERWRITE_SETTING_Prometheus_Enabled=true` that the vendor's compose turns on alongside it. It does not change the app's own security posture, it would take more than a third of the RAM budget, and its `node-exporter` service requires `privileged: true` plus `network_mode: host`, which the sandbox refuses outright. `Prometheus_Enabled` is therefore left at its shipped `false`.
- **Object storage for uploads.** The deploy guide "highly recommends using a dedicated object storage service such as Amazon S3, Google Cloud Storage (GCS), or MinIO", but the setting's shipped default is `GridFS` and the recommendation is about scale, not security. Keeping `GridFS` keeps the audit on the default code path. `deploy/lab-services/s3.yml` was not added for the same reason; it can be added later if a finding needs the S3 store.
- **SSO / an identity provider.** `deploy/lab-services/oidc.yml` was not added: every SSO backend (SAML, LDAP, OAuth) is off by default, the documented default is local password login, and Custom OAuth became a premium feature in 9.0 gated by the `oauth-enterprise` licence module, which this unlicensed workspace does not have. If a later stage needs a provider, the built-in GitLab backend takes a custom server URL (`API_Gitlab_URL`, `apps/meteor/server/lib/auth-providers/gitlab.ts:32`) and can be pointed at the mock.
- **A Rocket.Chat licence and cloud registration.** The workspace runs unlicensed Community edition and is not registered, so premium modules are gated off and the admin screen shows "Workspace not registered". Registration needs a Rocket.Chat Cloud account and an email round trip.
- **One real external host is reached, exactly once:** `https://collector.rocket.chat/`, during the app's first boot, by the product's own default statistics reporting. That call is what lifts the air-gap restriction that would otherwise block messaging; the app is detached from the only outward network immediately afterwards and reaches nothing thereafter (verified: DNS and HTTP both fail from the app). There is no lab stand-in: the token is signed by the vendor and `sendStats` has the URL hardcoded (`apps/meteor/server/lib/statistics/functions/sendUsageReport.ts:20`).

### Shipped check output
The target ships no `check --deploy` / `doctor` / `audit` command. What it does
ship is a startup self-check (`apps/meteor/server/startup/serverRunning.ts`),
which validates the Node and MongoDB versions and prints the banner; it passed
with no warning or deprecation notice:

```
|  Rocket.Chat Version: 9.1.0-develop                                                     |
|       NodeJS Version: 24.22.1 - x64                                                     |
|      MongoDB Version: 8.2.12                                                            |
|       MongoDB Engine: wiredTiger                                                        |
|             Site URL: http://127.0.0.1:39649                                            |
|      OpenSSL Version: 3.5.9                                                             |
|        FIPS Provider: Disabled                                                          |
|          Commit Hash: 9f3d6c8c48                                                        |
|        Commit Branch: develop                                                           |
```

The only other warning in the whole startup log is the cosmetic
`ADMIN_USERNAME` one described under `### Known issues / workarounds`.

### Deliberately not hardened beyond the docs
No WAF, no extra middleware, no additional or tightened security header, no
narrowed permission, no modified role, and no security setting turned on that
the vendor does not ship on by default. The CSP, `X-Frame-Options`,
`X-Content-Type-Options` and rate-limit behaviour observed on the wire are the
product's own. Traefik is configured as a plain reverse proxy (one router, one
service, a health check) with no filtering middleware, no header rewriting and
no `providers.docker`, so it forwards requests unmodified. The three
`OVERWRITE_SETTING_` values the lab sets (`Show_Setup_Wizard`, `SMTP_Host`,
`SMTP_Port`, `From_Email`) are deployment wiring, not hardening, and none of them
strengthens or weakens a security control.

## Documentation

### Sources
- `targets/rocket.chat/README.md` - product overview, the deployment and documentation links this stage followed, feature areas. Found in the repository.
- `targets/rocket.chat/SECURITY.md` - supported versions, how to report a vulnerability (HackerOne VDP, GitHub private advisories), disclosure policy. In the repository.
- `targets/rocket.chat/FEATURES.md` - the feature inventory (auth options, uploads, livechat, integrations, webhooks, roles and permissions, slash commands). In the repository.
- `targets/rocket.chat/docs/` - 50+ developer documents: `getting-started.md`, `backend-folder-structure.md`, `database-access.md`, `api-endpoint-migration.md`, `experimental-api-endpoints.md`, `service-brokers.md`, plus `docs/features/` (`mcp-server.md`, `oauth2-server.md`, `http-server.md`, `ddp-sessions.md`, `message-max-parse-length.md`, `ban-user.md`, `xmpp-server.md`, `ai-search-hybrid.md`, video conferencing, UIKit) and `docs/proposals/` (including `offline-license-capability-enforcement.md`, which documents the offline/air-gap egress rules). In the repository: this is the deepest per-feature documentation and the best starting point for stage 02.
- `targets/rocket.chat/apps/meteor/CHANGELOG.md` and `targets/rocket.chat/HISTORY.md` - the release history. The 9.0.0 entry is the most recent released one and lists the security-relevant breaking changes this build inherits (the `query`/`fields` REST parameters and `ALLOW_UNSAFE_QUERY_AND_FIELDS_API_PARAMS` removed, anonymous write removed, Custom OAuth gated behind a premium module, the legacy Meteor OAuth flow removed in favour of server-side Passport with PKCE, `/ufs` removed, Omnichannel off by default, `MESSAGE_MAX_PARSE_LENGTH` defaulting to 10000, Gravatar removed, Crowd removed). `targets/rocket.chat/.changeset/` holds **161** unreleased changesets, which is the diff between 9.0.0 and the audited `9.1.0-develop`.
- `http://127.0.0.1:39649/api/docs/json` and `/api-docs/` - the workspace's **own OpenAPI 3.1 document**, generated by this build: 493 documented paths with their parameters and response schemas, served unauthenticated. Generated from the audited code, so it matches the target exactly. Found by reading `apps/meteor/server/api/default/openApi.ts`.
- https://docs.rocket.chat/docs/rocketchat - user and administrator documentation (workspace administration, settings reference, permissions, omnichannel, apps). Linked from the README.
- https://developer.rocket.chat/docs/rocketchat and https://developer.rocket.chat/apidocs - developer documentation and the published REST API reference. Linked from the README.
- https://docs.rocket.chat/docs/secure-rocketchat and its sub-pages (password policy, 2FA, rate limiter, E2EE, ABAC, device management) - the security guide. Linked from the README's "Security and sovereignty".

### Version match
- **Exact:** everything inside `targets/rocket.chat/` (README, SECURITY.md, FEATURES.md, `docs/`, the changesets) and the live OpenAPI document, which this build generates from its own routes (`info.version` reports `9.1`).
- **Nearest, and what differs:** `apps/meteor/CHANGELOG.md` documents up to **9.0.0**; the audited build is `9.1.0-develop`, i.e. 9.0.0 plus the 161 unreleased changesets in `.changeset/`. Those changesets are the authoritative record of what is new in this build.
- **Unversioned:** `docs.rocket.chat` and `developer.rocket.chat` document the current release (8.x/9.x) with no per-version archive, and the deployment guide's examples pin `RELEASE=8.0.1`/`8.8.0`. They describe the product generally; where a 9.x default differs (Omnichannel now off, Custom OAuth now premium), the in-repo changelog is authoritative and was used instead.

### Searched
- The repository's `docs/`, `docs/features/`, `docs/proposals/`, `docs/adr/`, `docs/frontend/`, `docs/local-dev/`, the root `*.md` files, and `.github/` workflows (read for how the release image is built and tagged). No wiki is vendored in the checkout.
- https://docs.rocket.chat and https://developer.rocket.chat, both reachable from this scan, by product name and from the README's links.
- https://github.com/RocketChat/rocketchat-compose (the deployment compose repository, including `docs/external-mongo.md` and `docs/external-nats.md`), reachable.
- `WebSearch` for `OVERWRITE_SETTING_Show_Setup_Wizard`, the documented settings-via-environment mechanism, which confirmed the headless setup path.
- `https://hub.docker.com/v2/...` (the Docker Hub web API, to confirm the per-commit image tag): **unreachable from the scan** (the egress proxy refuses it with 403). The Docker daemon's own pull path works, so the tag was confirmed by pulling it and reading `star.json` and `/api/info` instead.
- No per-version documentation archive exists for this product, so a `9.1.0-develop` documentation set was not found and is not expected: `### Version match` records what was used in its place.

---

Blue Spider, a product of Kohi Research Corporation (kohirc.com). Copyright 2026 Kohi Research Corporation. All rights reserved. Blue Spider (TM) is a trademark of Kohi Research Corporation. Generated by Blue Spider; do not use or redistribute without attribution to Kohi Research Corporation.
