# cloud-pravaha-backend

Cloud Pravaha is a multi-tenant OpenTofu platform that deploys only **pinned public registry modules**. Nobody writes HCL. This repository builds one Go binary, `pravaha`, with three roles:

| Command | Runs | Where |
| --- | --- | --- |
| `pravaha central` | **Central plane:** web UI, users and tokens, the tenant directory (tenants, business units, memberships), and the wrapper that routes requests to tenants | Operated by the platform provider |
| `pravaha tenant` | **Tenant plane:** one client's backend, with its own PostgreSQL, stacks, runs, approvals, encrypted state, audit log, and the OIDC issuer its clouds trust | In the client's environment (the central tenant runs one too) |
| `pravaha runner` | **Runner:** executes OpenTofu for one tenant plane, polling it outbound | Next to the client's cloud accounts |

| Repository | Contents |
| --- | --- |
| `cloud-pravaha-backend` (this repo) | Central plane, tenant plane, runner |
| [`cloud-pravaha-modules`](../cloud-pravaha-modules) | The approved catalog, split by provider (`aws/`, `gcp/`, `azure/`, `common/`): public modules and providers pinned to exact versions, plus enforced security baselines |
| [`cloud-pravaha-web`](../cloud-pravaha-web) | React + TypeScript console |
| [`cloud-pravaha-test-resources`](../cloud-pravaha-test-resources) | Sample environments and stacks, attack specs, end-to-end tests, cloud trust setup |

## Architecture

```
 users ──HTTPS──▶ CENTRAL PLANE ───────────────── mTLS + per-request assertion ─────────────▶ TENANT PLANE "acme"
                  · web UI                         /api/v1/t/acme/... → /api/v1/...             · stacks, runs, approvals
                  · users, tokens                                                               · risk + policy on plans
                  · tenants, entities, roles      ───────────────────────────────────────────▶ TENANT PLANE "globex"
                  · the wrapper (routing)                                                      · own PostgreSQL, own state
                  └ PostgreSQL (identity only)                                                 · OIDC issuer for its clouds
                                                                                                      ▲ outbound HTTPS
                                                                                               RUNNER(S) ── cloud APIs
```

- **Tenants and entities.** A tenant is a client organisation. An entity is a business unit or team inside it. Stacks, environments (cloud integrations), runs and audit events all belong to an entity.
- **The wrapper.** Central authenticates the user and checks they have a role in the tenant. It then forwards the request to that tenant's backend over mTLS.
  - It strips the user's token and attaches a 60-second ES256 assertion: who the user is, their roles in that tenant, and the exact method and path.
  - The tenant plane accepts user requests only with central's client certificate plus a valid assertion. The assertion is checked for audience (this tenant), request binding and expiry, and can be used only once.
- **Data residency.** Central stores identity and the directory only. Stacks, plans, state and run logs stay in each tenant's own database.
- **Roles.**
  - **Platform:** `platform_admin` onboards tenants and holds everything `tenant_admin` and `auditor` have in every tenant. A platform admin also sees every business unit and can author stacks and runs in any of them, but signs approvals only with an explicit manager, FinOps or Security role. Their actions are audited as `platform-admin:<email>`.
  - **Tenant-wide:** `tenant_admin`, `finops`, `security`, `auditor`. They see every entity.
  - **Per entity:** `admin`, `manager`, `developer`, `viewer`. They see only their entity, and other entities' resources answer 404.
- **Risk and approvals.** Each plan is classified, and the risk decides which approvals it needs. Each step must be signed by a different person, and never by the run's author.

  | Risk | When | Approvals |
  | --- | --- | --- |
  | low | only additions in a non-production environment | manager |
  | medium | production environment, in-place changes, network resources, or more than 25 changes | manager + finops |
  | high | deletions or replacements, destroy runs, identity and access changes, or network exposure in production | manager + finops + security |

## How a change flows

1. **Spec.** A developer submits a stack spec listing catalog modules, literal inputs and `{"$ref": "module.output"}` wiring. Anything outside the catalog, version ranges, `${…}`/`%{…}` templates and unknown fields are rejected.
2. **Generated config.** The tenant plane generates `main.tf.json`: exact module, provider and engine pins, enforced baselines, workload-identity authentication only, and its own HTTP state backend.
3. **Plan.** A runner claims the job by polling outbound, runs `tofu init` with provider installation restricted to the allowlist, and verifies every downloaded module and provider (`depcheck`). It then plans with enforced state and plan encryption and uploads a summary with sensitive values removed.
4. **Policy and risk.** Policy blocks over-limit deletions, static-credential resources, open ingress and public buckets. Risk classification sets the approval chain.
5. **Approvals.** Every signature re-checks that the config and state are unchanged; a stale plan is discarded. The last signature queues the apply.
6. **Apply.** The runner verifies the saved plan's SHA-256 and applies exactly that plan.

## Quick start (local)

Requirements: Go 1.25+, Docker, OpenTofu 1.13.x, Node 20+.

```bash
./scripts/dev-up.sh
```

This starts the central plane on `http://127.0.0.1:8090` (plain HTTP is allowed on loopback only) and tenant **acme** on `https://localhost:8444`, each with its own database, plus a runner. It seeds:
- **Business units:** Payments and Data.
- **People:** one per role.
- **Environments and stacks:** two of each.

Tokens are written to `.dev/multi-tenant/tokens.env`.
1. Sign in as `ALICE` and plan `prod-naming`.
2. Approve as `MIKE` (manager), then as `FIONA` (finops).
3. Sign in as `EVE` to see that the Data unit cannot see Payments.

Use `DEV_CENTRAL_PORT` and `DEV_TENANT_PORT` to change ports.

## Evaluation install (Docker Compose)

The Compose file runs central, one tenant plane and a runner:

```bash
cp .env.example .env                                   # fill in the secrets
docker compose up -d --build central tenant
docker compose run --rm --no-deps central central bootstrap -email you@example.com
```

Then complete the setup:
1. **Sign in** at `https://localhost:8443` (the dev CA is in the `certs` volume).
2. **Onboard the tenant** under *Platform*: slug `main`, backend `https://tenant:9443`, and the CA from `/certs/ca.pem`.
3. **Register a runner** under *Tenant settings* and put its token in `.env`.
4. **Start it:** `docker compose up -d runner`.

`../cloud-pravaha-test-resources/e2e/compose-smoke.sh` runs this whole flow automatically.

**Images:**
- `server` (central and tenant): distroless, non-root, read-only, about 14 MB.
- `runner`: Alpine with only `git` and CA certificates added, because registry modules download from commit-pinned git sources. It runs non-root.

## Configuration

Secrets can be given directly or as `NAME_FILE` pointing to a mounted secret.

**Central plane**

| Variable | Purpose |
| --- | --- |
| `PRAVAHA_DATABASE_URL`, `PRAVAHA_MASTER_KEY` | Central's PostgreSQL. The key (32 random bytes, base64) seals the assertion signing key |
| `PRAVAHA_PUBLIC_URL` | URL users reach central at; also the assertion issuer |
| `PRAVAHA_TLS_CERT`, `PRAVAHA_TLS_KEY` | Required unless `PRAVAHA_INSECURE_HTTP=1` on a loopback listener |
| `PRAVAHA_CLIENT_CERT`, `PRAVAHA_CLIENT_KEY` | Central's mTLS client identity towards tenant planes |
| `PRAVAHA_WEB_DIR`, `PRAVAHA_LISTEN` | Built web UI; listen address (default `:8443`) |

**Tenant plane**

| Variable | Purpose |
| --- | --- |
| `PRAVAHA_TENANT` | This plane's tenant slug, as onboarded. Assertions must name it |
| `PRAVAHA_DATABASE_URL`, `PRAVAHA_MASTER_KEY` | The tenant's own PostgreSQL. The key seals saved plans and the OIDC signing key |
| `PRAVAHA_PUBLIC_URL` | URL runners and clouds reach this plane at. It is the OIDC issuer the tenant's clouds trust |
| `PRAVAHA_TLS_CERT`, `PRAVAHA_TLS_KEY` | Always required |
| `PRAVAHA_CENTRAL_URL` | Where to fetch central's JWKS (https, or http on loopback for development) |
| `PRAVAHA_CENTRAL_ISSUER` | The issuer central signs as (its public URL), if different from `PRAVAHA_CENTRAL_URL` |
| `PRAVAHA_CENTRAL_CLIENT_CA` | CA that issued central's client certificate. Only certificates from it, with client-auth usage, are accepted |
| `PRAVAHA_CENTRAL_CA_FILE`, `PRAVAHA_CENTRAL_JWKS_FILE` | Optional: CA for central's TLS; a static JWKS instead of fetching it |
| `PRAVAHA_CATALOG_DIR`, `PRAVAHA_TOFU_VERSION` | Catalog directory; exact OpenTofu version (default `1.13.2`) |

**Runner:** `PRAVAHA_SERVER_URL` (its tenant plane), `PRAVAHA_RUNNER_TOKEN`, `PRAVAHA_STATE_KEY` (32+ characters, shared by the pool, never seen by any plane), `PRAVAHA_CA_FILE`, `PRAVAHA_CATALOG_DIR` (pins the catalog locally), `PRAVAHA_PLUGIN_CACHE_DIR`, `PRAVAHA_WORK_DIR`.

## CLI

```
pravaha central | tenant | runner
pravaha central bootstrap -email admin@example.com     # first platform admin + token
pravaha audit verify [-central]                        # check a database's audit hash chain
pravaha catalog verify -dir ../cloud-pravaha-modules/catalog -online
pravaha dev-cert -dir certs -name tenant -host pravaha.acme.internal [-client]
```

## API (all through central)

| Method and path | Who | |
| --- | --- | --- |
| `GET /api/v1/me`, `GET/POST/DELETE /api/v1/me/tokens` | anyone signed in | Your tenants, entities and roles; your tokens |
| `GET/POST /api/v1/tenants`, `PUT /api/v1/tenants/{t}` | platform admin | Onboard tenants. The response includes the settings the tenant plane needs |
| `GET /api/v1/tenants/{t}/health` | tenant admin | Central reaches the tenant over mTLS and checks it reports the same slug |
| `GET/POST /api/v1/tenants/{t}/entities` | tenant admin | Business units |
| `GET/POST/DELETE /api/v1/tenants/{t}/members` | tenant admin | Grant tenant-wide or entity roles |
| `POST /api/v1/tenants/{t}/tokens` | tenant admin | First token for a member. Refused for people who also belong to another tenant |
| `/api/v1/t/{t}/…` | members of `t` | **The wrapper.** Forwards to the tenant plane's API below |

Tenant plane API (reached as `/api/v1/t/{t}/…`):
- `catalog`
- `environments`
- `stacks` (and `stacks/preview`, `stacks/{id}/runs`, `stacks/{id}/state-versions`)
- `runs/{id}`, `runs/{id}/logs`, `runs/{id}/approve` with `{"step": "manager"|"finops"|"security", "reason"}`, and `runs/{id}/discard`
- `audit`, `audit/verify`
- `runners`

Every handler checks the caller's role for the resource's entity.

## Tests

```bash
go test ./...                                         # unit tests: catalog layout, spec attacks, depcheck, assertions, risk, roles, ...
../cloud-pravaha-test-resources/e2e/run.sh            # 116 end-to-end checks: two tenants, real registry modules
../cloud-pravaha-test-resources/e2e/compose-smoke.sh  # the Docker Compose install
```

See [SECURITY.md](SECURITY.md) for the security controls and how they map to compliance frameworks.

## Roadmap

This build covers the tenancy core of the platform design. Coming next:
- Git integration and a contracts repository per tenant, with pull-based auto-deploy
- Temporal workflows and per-tenant buckets
- Backporting: importing existing cloud resources into IaC
- LLM integration with RAG
- SSO
- OPA policy sets
- Helm charts
- Separate plan and apply cloud roles
