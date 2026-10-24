# Helm charts

| Chart | Installs | Where |
| --- | --- | --- |
| `cloud-pravaha-central` | Central plane: web UI, identity, tenant directory, routing | Platform provider's cluster |
| `cloud-pravaha-tenant` | One tenant plane and its runners | Each client's cluster (the central tenant installs one too) |

Both charts:
- **Secrets:** read from existing Secrets; no secrets in values.
- **Pods:** run non-root with read-only file systems, all capabilities dropped and RuntimeDefault seccomp.
- **Certificates:** optionally issued by cert-manager. Rotated certificates are picked up without restarts.

## Central

```bash
kubectl -n cloud-pravaha-central create secret generic cloud-pravaha-central \
  --from-literal=database-url='postgres://…' --from-literal=master-key="$(openssl rand -base64 32)"
helm install pravaha ./cloud-pravaha-central -n cloud-pravaha-central \
  --set publicURL=https://pravaha.example.com --set tls.certManager.enabled=true \
  --set sso.issuer=https://acme.okta.com --set sso.clientID=…
```

## Tenant

The tenant chart needs:
- **The tenant slug**, as onboarded in central.
- **Central's URL.**
- **The CA that issued central's client certificate**, as a Secret with `ca.crt`. Only certificates from that CA can call the tenant's user API.
- **The tenant database and master key**, plus the runner token and state key.

```bash
helm install acme ./cloud-pravaha-tenant -n cloud-pravaha \
  --set tenant=acme --set publicURL=https://pravaha.acme.internal \
  --set central.url=https://pravaha.example.com \
  --set bucket.url='s3://acme-pravaha?region=eu-west-1' \
  --set temporal.address=temporal-frontend.temporal:7233 \
  --set runner.serviceAccountAnnotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::123456789012:role/pravaha-runner
```

Network policies let only central's namespace (`central.ingressFrom`) and the release's runners reach the tenant API. Runners accept no inbound traffic.
