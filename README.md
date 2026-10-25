# cloud-pravaha-backend

Cloud Pravaha is a multi-tenant OpenTofu platform that deploys only **pinned public registry modules**, called **kinds** (`S3Bucket`, `GKECluster`, ...). Nobody writes HCL: teams describe resources in small YAML contracts that hold only what differs from the defaults, and the platform generates the HCL. This repository builds one Go binary, `pravaha`, with three roles:

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

- **Hierarchy.**
  ```
  Tenant (a client company) ── cloud connections (AWS accounts, GCP projects, Azure subscriptions; each scoped to some or all entities)
    └─ Entity (a product; N per tenant) ── environments (connection + tier), shared by all its business units
         └─ Business unit (a unit inside the product; N per entity) ── stacks ── runs
  ```
  Stacks, runs and audit events belong to a business unit (BU) and record its entity. Environments belong to the entity and are shared by its BUs; they may use only connections the entity is allowed. Entity and BU slugs never coincide.
- **The wrapper.** Central authenticates the user and checks they have a role in the tenant. It then forwards the request to that tenant's backend over mTLS.
  - It strips the user's token and attaches a 60-second ES256 assertion: who the user is, their roles in that tenant, and the exact method and path.
  - The tenant plane accepts user requests only with central's client certificate plus a valid assertion. The assertion is checked for audience (this tenant), request binding and expiry, and can be used only once.
- **Data residency.** Central stores identity and the directory only. Stacks, plans, state and run logs stay in each tenant's own database, and optionally in the tenant's own bucket for state and plans.
- **Roles.**
  - **Platform:** `platform_admin` onboards tenants and holds everything `tenant_admin` and `auditor` have in every tenant. A platform admin also sees every business unit and can author stacks and runs in any of them, but signs approvals only with an explicit manager, FinOps or Security role. Their actions are audited as `platform-admin:<email>`.
  - **Tenant-wide:** `tenant_admin`, `finops`, `security`, `auditor`. They see every entity.
  - **Per entity or per BU:** `admin`, `manager`, `developer`, `viewer`. Roles granted on an entity are inherited by all its BUs. Members see only their BUs, and other BUs' resources answer 404.
- **Risk and approvals.** Each plan is classified, and the risk decides which approvals it needs. Each step must be signed by a different person, and never by the run's author.

  | Risk | When | Approvals |
  | --- | --- | --- |
  | low | only additions in a non-production environment | manager |
  | medium | production environment, in-place changes, network resources, or more than 25 changes | manager + finops |
  | high | deletions or replacements, destroy runs, identity and access changes, or network exposure in production | manager + finops + security |

## Policy sets (OPA/Rego)

Tenant admins and Security can add Rego policy sets (`package pravaha.policy`, rules in `deny`).
- **Scope:** the whole tenant, one entity or one BU.
- **Strength:** `hard` (blocks approval) or `advisory`.
- **Input:** each set sees `input.run` (operation, stack, BU, entity, environment, tier, author), `input.summary` (resource changes with non-sensitive planned values) and `input.cost`.
- **Safety:** sets compile when saved, run with a 2-second limit, and fail closed.
- **Dry run:** `POST /policies/test` evaluates a module against a past run.

Starter packs live in `cloud-pravaha-test-resources/policies`.

## Kinds, defaults and contracts

Every resource is a **kind**: a catalog entry in `cloud-pravaha-modules/catalog/modules/<cloud>/<name>.yaml` that wraps one public module at pinned versions, lists the inputs people may set (with the kind's defaults), the enforced security baseline, and the approved outputs.

Inputs are resolved in layers, each overriding the one before:

| Layer | Where | Example |
| --- | --- | --- |
| kind defaults | the kind's `inputs[].default` | `force_destroy: false` |
| tenant defaults | `tenants/<tenant>/defaults/<Kind>.yaml`, `spec:` | `tags: {cost-centre: acme-platform}` |
| tenant tier defaults | the same file, `tiers.prod:` / `tiers.nonprod:` | `force_destroy: false` in prod |
| the contract | the resource's `spec:` | `bucket: acme-orders-dev` |

Maps of strings (tags, labels) merge key by key; other values are replaced. Required inputs may be satisfied by a default. The enforced baseline cannot be touched at any layer, and the generated HCL notes which default layers a module used.

### Contracts repositories

Each tenant can keep its stacks as YAML contracts in a Git branch (GitHub, GitLab, or self-hosted either), **one resource per file**, Kubernetes style; see `cloud-pravaha-test-resources/contracts-example`:

```yaml
# stacks/retail/dev/payments/orders/db.yaml   <entity>/<environment>/<bu>/<stack>/<resource>.yaml
apiVersion: pravaha/v1
kind: RDSDatabase
metadata:
  name: orders-db          # defaults to the file name
spec:                      # only what differs from the defaults
  identifier: orders
  kms_key_id:
    ref: orders-key.key_arn                       # another resource of the stack
  master_password:
    secretRef: vault://kv/payments/orders-db#password   # never the value
imports:                   # optional: adopt existing resources
  - {to: aws_db_instance.this[0], id: orders}
```

- **The folder is the stack** (one state file). With `"layout": "nested"` the folders name the entity, its shared environment and the owning BU; with the default `"flat"` layout (`<path>/<stack>/<resource>.yaml`) each file names `metadata.environment` and `metadata.bu`, and they must agree.
- **Strict YAML.** Anchors, aliases, merge keys, custom tags, duplicate keys and unknown fields are refused. A stack with any problem is reported and not applied, never half-applied.
- **Pull-based sync:** the tenant plane polls the branch, outbound only, and downloads a snapshot when the commit changes (or right away on a GitHub push webhook).
- **Git-managed stacks** can't be edited in the UI or API; the source commit is recorded. With `auto_plan`, a plan is queued for every new or changed stack; with `auto_apply_low_risk`, the system signs low-risk plans, recorded as `system:auto-deploy:<step>`.
- A contract can't take over a stack managed in the UI, and removed stacks are reported as orphaned, never destroyed automatically.

API: `GET/PUT /contracts`, `PUT /contracts/token` (read-only token, sealed with the tenant master key, never returned), and `POST /contracts/sync`. The development-only `local` provider needs `PRAVAHA_ALLOW_LOCAL_CONTRACTS=1`.

### Generated HCL

The platform writes the stack's `main.tf` itself with HashiCorp's `hclwrite`: pinned engine, providers and modules, the enforced baseline first in each module, workload-identity providers only, and its own HTTP state backend. Every value from a contract or a default is a literal; `hclwrite` escapes `${` and `%{`, so data can never become an expression. The only expressions are references the platform builds from validated names.

## Secrets: OpenBao / Vault references

Secrets never go in Git or the platform's database. A contract passes `secretRef: vault://<mount>/<path>#<key>` (KV v2), and the generated HCL reads it with a `vault_kv_secret_v2` data source at plan time.

- **No stored Vault credentials.** The tenant configures only the address, the JWT auth mount and the role (Integrations → Secret store, `PUT /integrations/secret-store`). Runs log in with their own short-lived token from the tenant's OIDC issuer, issued for the store's own audience (default `pravaha-vault`), so a cloud token can never be replayed against Vault or the other way round. The `sub` claim names the entity, environment, stack and phase, so Vault policies can be scoped exactly.
- **Sensitive inputs** (marked `sensitive: true` in a kind) accept only a secretRef; literal values that look like credentials (cloud keys, private keys, JWTs, tokens) are refused everywhere.
- Values read from the store end up in state and saved plans, which are always encrypted.

## Module and policy releases

The platform builds what the tenant keeps in Git into **releases** and deploys them through the console (Tenant settings → Releases):

1. **Validate:** the catalog of kinds loads and passes its rules; this tenant's defaults target real kinds and pass the same checks as contract values.
2. **Vendor:** every approved module version and declared dependency is downloaded from the registry (or `PRAVAHA_REGISTRY_URL`, a mirror), pinned to the commit the registry points at.
3. **Pin nested modules:** starting from what each kind loads, nested registry modules are rewritten to vendored, approved versions (the highest approved version that satisfies the module's own constraint). Any other source (git, http, s3) fails the build, and configuration nothing loads is left out of the bundle.
4. **Check:** no loaded module runs commands (provisioners, the external data source), and every kind's inputs, baseline keys and outputs exist in each module version.
5. **Bundle and store:** one deterministic tarball named by its SHA-256, in the tenant bucket (S3, MinIO, GCS) or PostgreSQL, with a manifest carrying the catalog, this tenant's defaults and the package index.
6. **Activate, roll back:** someone (tenant admin or DevOps) requests activating a built release; it activates once enough people with the `devops` role approve (`approvals` on the source, 0–5; the requester and the author of a console change never count). Requesting an older release is a rollback. The defaults deploy with the release, so after activation nothing reads the modules repository or the registry until the next build.

Releases come from two flows:

- **Git first.** With `enabled`, every pull request to the source branch (and every push to it) is built automatically through the GitHub App webhooks. The pull request gets a `pravaha/release-<kind>` commit status and one comment with the checks. A new commit retires the pull request's older builds; closing it unmerged retires them all; forks and drafts are never built.
- **Console first.** Editing a kind, the tenant's defaults for a kind, or a policy set in the console (`POST /releases/{kind}/changes`) builds the change on top of the branch at once. Only a change that builds is committed: to a new branch with a pull request (GitHub App), or straight into the folder for the development-only `local` provider.

**Activating a release built from a pull request squash-merges it**, and only if the pull request's head is still the commit that was built; the merge commit is not built again. If the merge fails the release stays active and the console offers to merge again.

Runs then use **only** the deployed release: the generated config loads modules from `vendor/` and lists each package it needs with its checksum. The runner downloads the bundle once, extracts only those packages, verifies every checksum, and `tofu init` downloads no module from the internet. Because the config pins packages rather than release numbers, a deploy makes a waiting plan stale only if the modules that stack loads actually changed.

**Policy releases** do the same for Rego: `global/<set>.rego` (every tenant), `tenants/<tenant>/`, `tenants/<tenant>/entities/<entity>/` and `tenants/<tenant>/bus/<bu>/`, with optional `<set>_test.rego` (run on every build; a failing test stops the release) and `<set>.yaml` (`level: hard | advisory`, `description`). Deployed sets are read-only in the console.

**Caching.** Bundles are immutable and content-addressed. The tenant plane keeps them in memory (`PRAVAHA_BUNDLE_CACHE_MEMORY_MB`, default 256) and on disk (`PRAVAHA_BUNDLE_CACHE_DIR`, `PRAVAHA_BUNDLE_CACHE_DISK_MB`), runners keep their own disk cache, every copy is verified against its checksum when loaded, and concurrent misses share one read, so the bucket or database is read once per bundle. `GET /releases/cache` shows the hit counts.

API: `GET/PUT /releases/{modules|policies}/source`, `PUT …/source/token`, `POST …/builds`, `GET …/files?path=`, `POST …/changes`, `GET /releases/{kind}`, `GET /releases/{kind}/{id}`, `POST /releases/{kind}/{id}/request|approve|reject|override|merge`.

## Approvals page and overrides

The console's **Approvals** page lists everything waiting for a decision: plans that need manager, FinOps or Security signatures, and releases waiting for DevOps. Each shows who raised it, the steps already signed, and the people who can sign each remaining step (from `GET /api/v1/tenants/{t}/approvers` on central, which lists only approving roles).

People with the `devops` role can **override** a waiting plan or release, with a reason. A plan's remaining steps are recorded as `override:<who>:<step>`, a release records an `override` decision, both are audited (`run.override`, `release.override`) and announced. Overrides never bypass policy: only plans that passed policy can be overridden, and stale plans are still discarded.

## GitHub App and webhooks

Each tenant can connect its own GitHub App under **Integrations** (tenant admins). It needs:
- the App ID;
- the app's private key (`.pem`);
- a webhook secret;
- the installation ID, which is optional: it is detected from the contracts repository.

What the app is used for:
- **Authentication.** The contracts repository can use `"auth": "github_app"` instead of a personal access token. The tenant plane signs a 9-minute app JWT and exchanges it for a one-hour installation token, cached in memory.
- **Webhooks.** In the app, set the webhook URL to `<PRAVAHA_WEBHOOK_BASE_URL>/webhooks/github/<tenant>`, the content type to JSON, and the same secret.
  - Central keeps no secret. It relays the delivery unchanged to the tenant plane over mTLS, with a relay assertion bound to that tenant.
  - The tenant plane verifies `X-Hub-Signature-256` and drops duplicate delivery IDs.
  - A push to the contracts branch starts a sync at once. Pings are answered, installation events record the installation, and other events are logged for pull-request plans.
  - Verified deliveries are listed on the Integrations page.
- **Permissions and events.** Repository permissions: Contents: Read, Metadata: Read, Pull requests: Read & write, Checks: Read & write. Events: Push, Pull request, Issue comment. **Test connection** checks all of this.

**Where the settings live.**
- **With `PRAVAHA_ENV_FILE`** (a writable `.env`, for development or a single-host install): the console writes the `PRAVAHA_GITHUB_*` keys there, and the private key to a 0600 PEM file beside it. Both planes watch the file and reload within two seconds. Central also takes `PRAVAHA_WEBHOOK_BASE_URL` from it.
- **Without it** (for example Kubernetes): the settings are sealed in the tenant database.

Either way they are held in memory, so webhook deliveries and token minting never read the file or the database. For local development, `ngrok http 8090 --traffic-policy-file scripts/ngrok-webhooks.yml` exposes only `/webhooks/*`, and `scripts/dev-up.sh` picks up the tunnel or the `.env` value.

## Organisation and resource labels

- **Tenant:** a client company.
- **Entity:** one of its products, with its own infrastructure.
- **Business unit:** a unit inside an entity.
- **Environment:** belongs to an entity and is shared by every BU of that entity, for example retail's `dev`, `staging` and `prod`. It binds a cloud connection, a tier, a runner pool and guardrails.
  - Names are unique within the entity, so platform can also have `dev`.
  - Address an environment as `entity:name` when the name alone is ambiguous.
  - Tenant admins and the entity's admins manage environments, under Tenant settings → Organisation.
- **Stacks:** a stack names its owning BU and one of that BU's entity's environments (`{"name","bu","environment","spec"}`). The `bu` can be left out when the caller can write to only one BU of that entity.

Entity and BU slugs never collide within a tenant; central refuses either if the other already uses the slug.

Every resource a stack creates is labelled with `pravaha-tenant`, `pravaha-entity`, `pravaha-bu`, `pravaha-environment`, `pravaha-stack` and `managed-by=cloud-pravaha`:
- AWS gets them as provider `default_tags`;
- GCP gets them as provider `default_labels`;
- Azure modules get them merged into their `tags` input, and the platform labels win over user tags with the same key.

Values are normalised to the strictest rules, which are GCP's.

## Pull-request plans: apply before merge

With a GitHub contracts repository that uses the GitHub App, every pull request against the contracts branch goes through these steps:

1. **Plan.** Each changed contract gets a run that plans the pull request's version of the spec. A new stack is created as *proposed*.
2. **Report.** One comment on the pull request summarises each stack: status, risk, approvals signed and still needed, monthly cost, and a link to the run. A `pravaha/apply` commit status tracks progress.
3. **Approve and apply.** The usual risk-based approvals apply, in the console or in Slack. Each apply uses exactly the pull request's spec, and that spec becomes the stack's.
4. **Merge.** When every changed stack has applied, the status turns green and the platform squash-merges the pull request, pinned to the applied commit. The branch therefore only ever holds what is deployed. If the merge fails, the pull request is marked as applied, with a comment.
5. **New commits and closing.** A new commit discards the old plans and plans again. `/plan` in a comment does the same. Closing without merging discards the plans and removes proposed stacks that never applied.
6. **Not planned:** pull requests from forks, and drafts.

Require the `pravaha/apply` status in the contracts branch's protection rules, so nobody merges before the apply.

## Self-service through Git

When the contracts repository is on GitHub with the app, **New stack** (and assistant drafts) offers **Open a pull request** instead of creating the stack directly. The platform:
1. creates a `pravaha/<stack>-<id>` branch;
2. commits the contract at its folder path, `<entity>/<environment>/<bu>/` in the nested layout;
3. opens a pull request that names the requester.

The pull request then follows the flow above. The API is `POST /stacks/propose`, with the same body as `POST /stacks`. The app needs **Contents: write**, **Pull requests: write** and **Commit statuses: write**. The connection test checks what the installation actually granted, reports permission updates the installation has not accepted yet, and flags permissions the platform does not need.

## Notifications and Slack

Every event of interest is recorded in the notification centre: the bell in the console, filtered by business unit like everything else.
- runs awaiting approval, approved, auto-approved, applied, failed, blocked by policy or rejected;
- drift found;
- pull requests planned or merged;
- contracts sync failures.

**Slack alerts.** With an incoming webhook (Integrations → Slack, or `PRAVAHA_SLACK_WEBHOOK_URL` in the env file), every notification is also posted to a channel.

**Approve and reject from Slack.** With a Slack app's signing secret and bot token (scopes `users:read`, `users:read.email`) stored on central, approval requests carry **Approve as …** and **Reject** buttons. Slack calls `POST /webhooks/slack/{tenant}` on central, which:
1. verifies `X-Slack-Signature`, rejecting requests older than five minutes;
2. resolves the clicking user's email and maps it to a Cloud Pravaha user;
3. calls the tenant plane as that user, exactly like the console.

Role checks, separation of duties and the audit trail are unchanged. The approval is recorded under the person's name with the reason "approved in Slack". Unknown Slack users are refused.

## Backporting: importing existing resources

A stack spec can list `imports`: an address inside one of the stack's catalog modules and the cloud ID of a resource that already exists. The platform generates OpenTofu `import` blocks, so the plan adopts those resources into the module's state instead of creating them.

```json
"imports": [{ "to": "module.network.aws_vpc.this[0]", "id": "vpc-0a1b2c3d4e5f67890" }]
```

Imports raise risk to at least medium. A new hard policy rule, `import-destroys`, blocks any import the plan would delete or replace. That happens when the module's inputs don't match the existing resource; fix the inputs and plan again.

## Drift detection

A drift run (`{"operation":"drift"}`) is a refresh-only plan. It compares real infrastructure with state and ends as `no_drift` or `drifted`, listing the resources changed outside OpenTofu. It never changes anything and needs no approvals.

Each stack can schedule checks (`PUT /stacks/{id}/drift` with `{"interval_minutes": 60, "auto_remediate": true}`; minimum 5 minutes). With auto-remediation, a drifted check queues a normal plan, which still goes through the risk-based approval chain.

## Assistant (LLM with RAG)

The assistant answers questions about the platform and drafts stacks. It is off by default. To enable it on a tenant plane, give it an Anthropic API key: `PRAVAHA_ASSISTANT_API_KEY`, or `PRAVAHA_ASSISTANT_API_KEY_FILE`.

- **Retrieval.** A BM25 index runs inside the tenant plane, so no embedding service is needed. It covers:
  - the approved catalog: each module's inputs, constraints, enforced baseline and outputs;
  - a built-in platform guide;
  - Markdown runbooks from `PRAVAHA_ASSISTANT_DOCS_DIR`;
  - the tenant's OPA policies and risk policy;
  - the stacks and environments the caller can see.

  The index is rebuilt per question from the caller's view, so it never retrieves another BU's stacks.
- **Model.** Claude (`claude-opus-5-5` by default, effort `medium`) through the official Go SDK. It has two tools:
  - `search_knowledge` retrieves more passages;
  - `propose_stack` validates a draft against the catalog and an environment the caller can write to, using the same code as `stacks/preview`. The draft is returned only once it is valid.

  Answers cite passages as `[catalog:aws-eks]`.
- **No side effects.** The assistant never creates, plans or applies anything. A draft opens in the stack editor, and the person submits it through the normal RBAC, risk and approval chain.
- **Data and audit.** A question sends the question and the retrieved passages to the Anthropic API, or to a gateway set with `PRAVAHA_ASSISTANT_BASE_URL`. Each question is audited as `assistant.ask` with a hash and the token counts, never the text. Questions are limited to 60 per user per hour.

`POST /api/v1/t/{t}/assistant/ask` with `{"question", "history": [{"role","text"}]}` streams newline-delimited JSON: `status` events, then one `answer` with `text`, `sources`, `draft` and `usage`.

## Configuration as code (OpenTofu/Terraform provider)

[`terraform-provider-pravaha/`](terraform-provider-pravaha/README.md) manages a tenant's configuration from OpenTofu or Terraform:
- entities and business units
- role grants
- cloud connections
- environments
- OPA policy sets
- the risk policy

It also has a catalog data source. Stacks are not provider resources. They stay in the contracts repository or the console, so infrastructure changes always go through plans and approvals.

## How a change flows

1. **Spec.** A contract (or the console) lists resources by kind with only the values that differ from the defaults, `ref` wiring and `secretRef`s. Anything outside the catalog, version ranges, `${…}`/`%{…}` templates, literal credentials and unknown fields are rejected.
2. **Generated config.** The tenant plane resolves defaults and generates `main.tf`: exact module, provider and engine pins, enforced baselines, workload-identity authentication only, its own HTTP state backend, and the vendored module packages with their checksums.
3. **Plan.** A runner claims the job by polling outbound, extracts and verifies the release's module packages, runs `tofu init` with provider installation restricted to the allowlist, and verifies every module and provider (`depcheck`). It then plans with enforced state and plan encryption and uploads a summary with sensitive values removed.
4. **Policy and risk.** Policy blocks over-limit deletions, static-credential resources, open ingress and public buckets. Risk classification sets the approval chain.
5. **Approvals.** Every signature re-checks that the config and state are unchanged; a stale plan is discarded. The last signature queues the apply.
6. **Apply.** The runner verifies the saved plan's SHA-256 and applies exactly that plan.

## Quick start (local)

Requirements: Go 1.25+, Docker, OpenTofu 1.13.x, Node 20+.

```bash
./scripts/dev-up.sh
```

This starts the central plane on `http://127.0.0.1:8090` (plain HTTP is allowed on loopback only) and tenant **acme** on `https://localhost:8444`, each with its own database, plus a runner. It seeds:
- **Entities and BUs:** Retail (Payments, Checkout) and Platform (Data).
- **Cloud connections:** four samples.
- **People:** one per role, including an entity-level manager (`RITA`).
- **Environments and stacks:** a few of each.

Tokens are written to `.dev/multi-tenant/tokens.env`.
1. Sign in as `ALICE` and plan `prod-naming`.
2. Approve as `MIKE` (manager), then as `FIONA` (finops).
3. Sign in as `EVE` to see that the Data BU cannot see Retail.

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

## Kubernetes

Helm charts for the central plane and for a tenant plane with its runners are in [`deploy/helm`](deploy/helm). They support cert-manager, network policies and hardened pod security. TLS certificates, central's mTLS client certificate and the trusted client CA reload from disk when rotated, with no restart needed.

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

**SSO and SCIM (central)**

| Variable | Purpose |
| --- | --- |
| `PRAVAHA_OIDC_ISSUER`, `PRAVAHA_OIDC_CLIENT_ID` | Enables "Sign in with SSO" (OIDC authorization code + PKCE). Register `<PRAVAHA_PUBLIC_URL>/auth/callback` as the redirect URI |
| `PRAVAHA_OIDC_CLIENT_SECRET` | For confidential clients (`_FILE` supported); public clients rely on PKCE |
| `PRAVAHA_OIDC_ALLOWED_DOMAINS` | Optional comma-separated email domains |
| `PRAVAHA_OIDC_TRUST_UNVERIFIED_EMAIL=1` | For IdPs that omit `email_verified` (for example Entra ID) |
| `PRAVAHA_OIDC_LABEL` | Button text |

SSO only authenticates: users must already exist (added by a tenant admin, or provisioned by SCIM). Sessions last 12 hours and are revoked on sign-out.

SCIM 2.0 lives at `<central>/scim/v2`; create its bearer token with `pravaha central scim-token -name okta`. Users are provisioned, and deactivating one revokes all their tokens. Groups named `pravaha:<tenant>:<role>`, `pravaha:<tenant>:entity:<slug>:<role>` or `pravaha:<tenant>:bu:<slug>:<role>` grant that role to their members, and removing a member removes only that grant.

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
| `PRAVAHA_BUCKET_URL` | Optional tenant bucket for state versions and saved plans: `s3://bucket[/prefix]?endpoint=https://…&region=…` (AWS S3, MinIO, Ceph, SeaweedFS, GCS interoperability). The database then keeps only keys and checksums |
| `PRAVAHA_TEMPORAL_ADDRESS`, `PRAVAHA_TEMPORAL_NAMESPACE` | Optional Temporal frontend (`host:7233`) and namespace. With it, each run is a durable workflow `run-<id>` that owns its timers (planning silence, approval expiry, apply timeout), and drift checks come from a cron workflow on task queue `pravaha-<tenant>`. Without it, the built-in database reaper and scheduler do the same |
| `PRAVAHA_BUCKET_ACCESS_KEY`, `PRAVAHA_BUCKET_SECRET_KEY` | Bucket credentials (use `_FILE` variants); `PRAVAHA_BUCKET_CREATE=1` creates the bucket on start |
| `PRAVAHA_ASSISTANT_API_KEY` | Optional Anthropic API key (use `_FILE`). Setting it enables the assistant |
| `PRAVAHA_ASSISTANT_MODEL`, `PRAVAHA_ASSISTANT_EFFORT` | Model (default `claude-opus-5-5`) and effort (`low`…`max`, default `medium`) |
| `PRAVAHA_ASSISTANT_BASE_URL` | Optional API gateway (https; plain http only on loopback). Server-side refusal fallbacks are used only against the Anthropic API directly; `PRAVAHA_ASSISTANT_FALLBACKS=0` turns them off |
| `PRAVAHA_ENV_FILE` | Optional writable `.env` for integration settings (`PRAVAHA_GITHUB_APP_ID`, `PRAVAHA_GITHUB_APP_INSTALLATION_ID`, `PRAVAHA_GITHUB_API_URL`, `PRAVAHA_GITHUB_APP_PRIVATE_KEY_FILE`, `PRAVAHA_GITHUB_WEBHOOK_SECRET`), watched and hot-reloaded. Without it, they are sealed in the database |
| `PRAVAHA_ASSISTANT_DOCS_DIR` | Directory of extra Markdown files (runbooks, conventions) to index |

**Runner:** `PRAVAHA_RUNNER_CONCURRENCY` sets how many runs one runner executes at once. The default is 2, the maximum 16. Each run gets its own work directory and TMPDIR, removed afterwards. Environments can limit what one run creates and imports with `max_creates` and `max_imports`, where 0 means no limit. Other settings: `PRAVAHA_SERVER_URL` (its tenant plane), `PRAVAHA_RUNNER_TOKEN`, `PRAVAHA_STATE_KEY` (32+ characters, shared by the pool, never seen by any plane), `PRAVAHA_CA_FILE`, `PRAVAHA_CATALOG_DIR` (pins the catalog locally), `PRAVAHA_PLUGIN_CACHE_DIR`, `PRAVAHA_WORK_DIR`.

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
| `GET/POST /api/v1/tenants/{t}/entities` | tenant admin | Entities (companies) |
| `GET/POST /api/v1/tenants/{t}/bus` | tenant admin | Business units (products) under an entity |
| `GET/POST/DELETE /api/v1/tenants/{t}/members` | tenant admin | Grant tenant-wide, entity or BU roles (`{"email","role","entity"?,"bu"?}`) |
| `POST /api/v1/tenants/{t}/tokens` | tenant admin | First token for a member. Refused for people who also belong to another tenant |
| `/api/v1/t/{t}/…` | members of `t` | **The wrapper.** Forwards to the tenant plane's API below |

Tenant plane API (reached as `/api/v1/t/{t}/…`):
- `catalog`
- `connections` (tenant admins register and delete unused ones; everyone reads)
- `environments` (`{"name","entity","tier","connection",…}`, shared by the entity's BUs; addressed by ID or `entity:name`; DELETE only without stacks)
- `stacks` (and `stacks/preview`, `stacks/{id}/runs`, `stacks/{id}/state-versions`)
- `runs/{id}`, `runs/{id}/logs`, `runs/{id}/approve` with `{"step": "manager"|"finops"|"security", "reason"}`, and `runs/{id}/discard`
- `audit`, `audit/verify`
- `runners`
- `assistant`, `assistant/ask`

Every handler checks the caller's role for the resource's entity.

## Tests

```bash
go test ./...                                         # unit tests: catalog layout, spec attacks, depcheck, assertions, risk, roles, ...
../cloud-pravaha-test-resources/e2e/run.sh            # 190+ end-to-end checks: two tenants, real registry modules
../cloud-pravaha-test-resources/e2e/compose-smoke.sh  # the Docker Compose install
```

See [SECURITY.md](SECURITY.md) for the security controls and how they map to compliance frameworks.

## Roadmap

Coming next:
- State diff between versions and rollback
- Policy exemptions and scan hooks
- Resource discovery for backporting (listing a cloud account's resources to suggest imports)
