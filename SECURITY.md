# Security controls

Cloud Pravaha runs infrastructure code with cloud admin rights, so its controls are built into the product rather than left to configuration. This page lists each control, where it lives in the code, and how it is tested. The last section maps the controls to common compliance frameworks.

The mapping helps your own audit evidence. It is not a certification: SOC 2, ISO 27001 and similar attestations cover your organisation's operation of the platform, not the software alone.

## Controls

| # | Control | Implementation | Verified by |
| --- | --- | --- | --- |
| 1 | **Public, pinned modules only.** No custom modules, git, HTTP, S3 or private-registry sources; no version ranges | `internal/spec` (spec validation), catalog in `cloud-pravaha-modules` | `spec_test.go`, `attacks/*.json` in e2e |
| 2 | **No user-supplied code or expressions.** Config is generated as JSON; `${…}` and `%{…}` are rejected in every string and key; module wiring only through validated `$ref` | `spec.noTemplates`, `spec.Generate` | `TestRejectsAttacks` |
| 3 | **Supply-chain check after download.** Every nested module must be an approved registry version or stay inside its package; every locked provider must be allowlisted at its pin; provisioners and the `external` data source are rejected | `internal/depcheck` | `depcheck_test.go`, real AWS/GCP/Azure module trees |
| 4 | **Provider install allowlist.** The runner's CLI config allows only allowlisted providers to be installed | `runner.writeFiles` | e2e |
| 5 | **Engine pinning.** `required_version` and a runner-side check enforce one exact OpenTofu version | `spec.Generate`, `runner.checkTofuVersion` | e2e |
| 6 | **Security baselines.** Catalog `enforced` inputs (encryption, public access blocks, flow logs, TLS, telemetry off) cannot be overridden | catalog + `spec.Validate` | `TestEnforcedBaselineAndReferences`, e2e |
| 7 | **No stored cloud credentials.** Environments accept identifiers only (strict decoding rejects keys, secrets and endpoint overrides). Runs authenticate through per-run ES256 OIDC tokens (1 hour) or the runner's own workload identity | `spec/cloud.go`, `internal/oidc` | `TestCloudRejectsSecrets`, e2e |
| 8 | **Clean runner environment.** Fresh `0700` directory per run, deleted afterwards; minimal environment variables (no inherited cloud credentials); private `HOME` and `TMPDIR`; non-root container | `runner.buildEnv` | e2e checks directories are removed |
| 9 | **Encryption in transit.** TLS 1.2+ required; plain HTTP refused except on loopback in development; HSTS | `config.LoadServer`, `api.Run` | e2e |
| 10 | **State encryption.** OpenTofu client-side state and plan encryption is enforced (`enforced = true`) with per-stack keys derived on runners. The control plane stores ciphertext only | `runner.buildEnv` | e2e reads the database |
| 11 | **Saved plans.** Sealed with AES-256-GCM bound to the run ID and SHA-256. Checksum verified on download; deleted when the run ends | `internal/secure`, `api/agent.go` | `secure_test.go`, e2e |
| 12 | **Stale-plan protection.** Approval and apply re-check the generated-config hash and the state serial; OpenTofu also refuses stale saved plans | `api.approveRun`, `api.startJob` | e2e |
| 13 | **Authentication.** Central issues random 256-bit bearer tokens, stored as SHA-256 hashes, valid for at most 90 days, and revocable. 10 failed attempts per minute locks an IP out for 5 minutes and is audited. Tenant planes never receive user tokens | `central`, `secure` | e2e |
| 14 | **Least privilege.** Roles are scoped by platform, tenant and entity (business unit). Run tokens are scoped to one run and stack. State writes are allowed only while applying an approved plan, and only by the run holding the lock | `identity`, `api` | `identity_test.go`, e2e |
| 15 | **Separation of duties.** The run's author cannot sign any approval, and one person signs at most one step of a run. Both are checked under a row lock, with a unique constraint as backstop | `store.Approve`, schema | e2e |
| 16 | **Change guardrails.** Per-environment deletion limit, destroy runs off by default, one active run per stack (database-enforced), stack spec frozen while a plan awaits approval | `policy`, schema | `policy_test.go`, e2e |
| 17 | **Policy on plans.** Blocks static-credential resources, internet-open ingress, public S3 and GCS buckets, and over-limit deletions | `internal/policy` | `policy_test.go`, e2e |
| 18 | **Tamper-evident audit log.** SHA-256 hash chain; a database trigger blocks `UPDATE`, `DELETE` and `TRUNCATE`; verify through the API, UI or `pravaha audit verify` | `internal/audit`, migration | `audit_test.go`, e2e |
| 19 | **Secret redaction.** Known secrets and secret-shaped strings (cloud keys, JWTs, private keys, platform tokens) are removed from logs on the runner and again on the server; sensitive plan values never leave the runner | `internal/redact`, `runner.Summarize` | `redact_test.go`, `summary_test.go`, e2e |
| 20 | **Hardened HTTP.** CSP, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, `no-store` on the API; strict JSON with size limits; server timeouts | `api.securityHeaders` | manual |
| 21 | **Network posture.** Runners connect outbound only and can sit in private subnets; runner pools isolate environments | runner design | — |
| 22 | **Minimal dependencies.** Backend: Go standard library plus `pgx`. Web: React only. Images: distroless server, Alpine runner with `git` only | `go.mod`, `package.json`, `Dockerfile` | `npm audit`, `go mod verify` |
| 23 | **Tenant isolation.** Each tenant runs its own backend and database, so stacks, plans, state and logs never share storage. Central holds identity and the directory only | architecture | e2e checks central's schema |
| 24 | **Authenticated routing.** Tenant planes accept user requests only over mTLS with central's client-auth certificate, plus an ES256 assertion. The assertion has a 60-second lifetime, names this tenant (audience), is bound to the method and path, and can be used once. Central strips the user's token | `central` (wrapper), `identity`, `api.authUser` | `identity_test.go`, e2e |
| 25 | **Entity scoping.** Every stack, environment, run and audit event belongs to a business unit. Members see only their units, and other units' resources answer 404 so they cannot be discovered. Tenant-wide roles (`tenant_admin`, `finops`, `security`, `auditor`) see all units | `identity`, `api` | e2e |
| 26 | **Risk-based approvals.** Plans are classified low, medium or high, which requires manager; manager + finops; or manager + finops + security. Production tiers, deletions, IAM and network exposure raise the risk | `internal/risk` | `risk_test.go`, e2e |
| 27 | **Platform admin scope.** Platform admins act as tenant admin and auditor in every tenant and can author stacks and runs in any unit. They cannot sign approval steps without an explicit membership, so separation of duties holds. Their actions in a tenant are audited as `platform-admin:<email>`. Tenant admins cannot mint tokens for people who also belong to another tenant | `identity`, `central` | `identity_test.go`, e2e |
| 28 | **Per-tenant cloud trust.** Each tenant plane is its own OIDC issuer, so a cloud trusts only its own tenant's runs, never central | `oidc`, `api` | e2e |

## Compliance mapping

| Framework | Relevant controls |
| --- | --- |
| SOC 2 (2017 TSC) CC6.1 logical access | 7, 13, 14, 24, 25, 27 |
| SOC 2 CC6.1 / ISO 27001 A.8.3 information access restriction and tenant segregation | 23, 24, 25, 28 |
| SOC 2 CC6.6 / CC6.7 boundaries and transmission | 9, 21 |
| SOC 2 CC6.8 unauthorised software | 1, 2, 3, 4, 5 |
| SOC 2 CC7.2 monitoring | 18, 13 (lockout events) |
| SOC 2 CC8.1 change management | 12, 15, 16, 17, 26 |
| ISO/IEC 27001:2022 A.5.15–A.5.18 access control | 13, 14 |
| ISO 27001 A.8.9 configuration management | 1, 5, 6 |
| ISO 27001 A.8.15 logging | 18, 19 |
| ISO 27001 A.8.24 cryptography | 9, 10, 11 |
| ISO 27001 A.8.32 change management | 12, 15, 16, 26 |
| ISO 27001 A.5.3 segregation of duties | 15, 26 |
| NIST SSDF / SLSA dependency integrity | 1, 3, 4, 22 |
| CIS Benchmarks (cloud resources) | 6, 17 |
| PCI DSS v4.0 req. 3, 4, 7, 8, 10 | 10–11, 9, 14, 13, 18 |

## Your responsibilities when you operate it

- Keep `PRAVAHA_MASTER_KEY` and `PRAVAHA_STATE_KEY` in a secret manager, and back them up. Losing the state key makes state unreadable.
- Use a publicly trusted TLS certificate when clouds need to reach the OIDC issuer.
- Run each PostgreSQL (central and every tenant) with encryption at rest, backups and network isolation, and export the audit logs to your SIEM.
- Issue central's mTLS client certificate from a dedicated CA, and give tenant planes only that CA as `PRAVAHA_CENTRAL_CLIENT_CA`.
- Grant cloud roles only what your catalog modules need. Scope trust policies to environment and stack subjects.
- Review catalog changes in `cloud-pravaha-modules` through pull requests with required reviewers.

## Reporting a vulnerability

Report vulnerabilities privately to the maintainers. Do not open a public issue.
