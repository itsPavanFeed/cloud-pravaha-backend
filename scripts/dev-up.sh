#!/usr/bin/env bash
# Local multi-tenant development stack, all on loopback:
#   central plane   http://127.0.0.1:8090   web UI, identity, routing (plain HTTP allowed on loopback only)
#   tenant "acme"   https://localhost:8444  its own database, state and runner; reached by central over mTLS
# Seeds entities and business units, cloud connections and one person per role. Tokens are
# written to .dev/tokens.env (mode 0600).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(cd .. && pwd)"
DEV="$PWD/.dev/multi-tenant"
mkdir -p "$DEV" && chmod 700 "$PWD/.dev" "$DEV"
PG_NAME=pravaha-dev-mt-pg
PG_PORT="${DEV_PG_PORT:-55434}"
CP="${DEV_CENTRAL_PORT:-8090}"
TP="${DEV_TENANT_PORT:-8444}"
C="$DEV/certs"

[[ -f "$DEV/secrets.env" ]] || {
  umask 077
  cat >"$DEV/secrets.env" <<EOT
PG_PASS=$(openssl rand -hex 16)
CENTRAL_MASTER_KEY=$(openssl rand -base64 32)
ACME_MASTER_KEY=$(openssl rand -base64 32)
PRAVAHA_STATE_KEY=$(openssl rand -hex 32)
EOT
}
# shellcheck disable=SC1091
source "$DEV/secrets.env"

if ! docker ps --format '{{.Names}}' | grep -qx "$PG_NAME"; then
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
  docker run -d --name "$PG_NAME" -e POSTGRES_PASSWORD="$PG_PASS" \
    -v pravaha-dev-mt-pg:/var/lib/postgresql/data -p "127.0.0.1:$PG_PORT:5432" postgres:16-alpine >/dev/null
fi
until docker exec "$PG_NAME" pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
sleep 1
FRESH=""
for db in central acme; do
  if ! docker exec "$PG_NAME" psql -U postgres -Atc "SELECT 1 FROM pg_database WHERE datname='$db'" | grep -q 1; then
    docker exec "$PG_NAME" psql -U postgres -qc "CREATE DATABASE $db"
    FRESH=1
  fi
done
dburl() { echo "postgres://postgres:$PG_PASS@127.0.0.1:$PG_PORT/$1?sslmode=disable"; }

go build -o bin/pravaha ./cmd/pravaha
WEB="$ROOT/cloud-pravaha-web"
if [[ -d "$WEB" ]]; then (cd "$WEB" && { [[ -d node_modules ]] || npm ci; } && npm run build >/dev/null); fi
bin/pravaha dev-cert -dir "$C" -name central-client -client >/dev/null
bin/pravaha dev-cert -dir "$C" -name acme -host localhost,127.0.0.1 >/dev/null
TOFU_VERSION="$(tofu version -json | python3 -c 'import sys,json;print(json.load(sys.stdin)["terraform_version"])')"
CENTRAL=http://127.0.0.1:$CP

PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null; wait 2>/dev/null' EXIT INT TERM

# The assistant: a real key in PRAVAHA_ASSISTANT_API_KEY is passed through;
# DEV_ASSISTANT=fake uses the scripted stand-in from the e2e test instead.
if [[ "${DEV_ASSISTANT:-}" == fake ]]; then
  python3 "$ROOT/cloud-pravaha-test-resources/e2e/fake-claude.py" 18998 dev-fake-key >"$DEV/fake-claude.log" 2>&1 &
  PIDS+=($!)
  export PRAVAHA_ASSISTANT_API_KEY=dev-fake-key PRAVAHA_ASSISTANT_BASE_URL=http://127.0.0.1:18998
fi

# Webhooks from GitHub need a public address: PRAVAHA_WEBHOOK_BASE_URL, or an
# ngrok tunnel to the central port if one is running (ngrok http $CP).
if [[ -z "${PRAVAHA_WEBHOOK_BASE_URL:-}" ]]; then
  PRAVAHA_WEBHOOK_BASE_URL=$(curl -fsS http://127.0.0.1:4040/api/tunnels 2>/dev/null | python3 -c '
import json,sys
for t in json.load(sys.stdin).get("tunnels",[]):
    if t.get("public_url","").startswith("https://") and t.get("config",{}).get("addr","").endswith(":'"$CP"'"):
        print(t["public_url"]); break' 2>/dev/null || true)
fi
export PRAVAHA_WEBHOOK_BASE_URL
# Integration settings (GitHub App, webhook URL) live in .env and are hot-reloaded.
export PRAVAHA_ENV_FILE="${PRAVAHA_ENV_FILE:-$PWD/.env}"
[[ -f "$PRAVAHA_ENV_FILE" ]] || (umask 077; : > "$PRAVAHA_ENV_FILE")
HOOK_FROM_ENV=$(sed -n 's/^PRAVAHA_WEBHOOK_BASE_URL=//p' "$PRAVAHA_ENV_FILE" | tail -1)
[[ -n "$HOOK_FROM_ENV" ]] && PRAVAHA_WEBHOOK_BASE_URL="$HOOK_FROM_ENV"

PRAVAHA_DATABASE_URL="$(dburl central)" PRAVAHA_MASTER_KEY="$CENTRAL_MASTER_KEY" PRAVAHA_LISTEN=127.0.0.1:$CP \
PRAVAHA_PUBLIC_URL="$CENTRAL" PRAVAHA_INSECURE_HTTP=1 PRAVAHA_WEB_DIR="$WEB/dist" \
PRAVAHA_CLIENT_CERT="$C/central-client.pem" PRAVAHA_CLIENT_KEY="$C/central-client-key.pem" \
  bin/pravaha central >"$DEV/central.log" 2>&1 &
PIDS+=($!)
PRAVAHA_DATABASE_URL="$(dburl acme)" PRAVAHA_MASTER_KEY="$ACME_MASTER_KEY" PRAVAHA_TENANT=acme \
PRAVAHA_LISTEN=127.0.0.1:$TP PRAVAHA_PUBLIC_URL=https://localhost:$TP PRAVAHA_TLS_CERT="$C/acme.pem" PRAVAHA_TLS_KEY="$C/acme-key.pem" \
PRAVAHA_CENTRAL_URL="$CENTRAL" PRAVAHA_CENTRAL_CLIENT_CA="$C/ca.pem" \
PRAVAHA_CATALOG_DIR="$ROOT/cloud-pravaha-modules/catalog" PRAVAHA_TOFU_VERSION="$TOFU_VERSION" \
  bin/pravaha tenant >"$DEV/tenant-acme.log" 2>&1 &
PIDS+=($!)
until curl -fsS "$CENTRAL/healthz" >/dev/null 2>&1 && curl -fsS --cacert "$C/ca.pem" https://localhost:$TP/healthz >/dev/null 2>&1; do sleep 0.5; done

call() { local tok=$1 m=$2 p=$3; shift 3; curl -fsS -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' -X "$m" "$CENTRAL$p" ${1:+--data-binary "$1"}; }
J() { python3 -c 'import sys,json;print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }
# Seed on a fresh database (tokens from an older database would not work).
if [[ -n "$FRESH" || ! -f "$DEV/tokens.env" ]]; then
  RES="$ROOT/cloud-pravaha-test-resources"
  ROOT_TOKEN=$(PRAVAHA_DATABASE_URL="$(dburl central)" bin/pravaha central bootstrap -email root@platform.local -ttl-days 30 2>/dev/null)
  CA_JSON=$(python3 -c 'import json,sys;print(json.dumps(open(sys.argv[1]).read()))' "$C/ca.pem")
  call "$ROOT_TOKEN" POST /api/v1/tenants "{\"slug\":\"acme\",\"name\":\"Acme Corp\",\"backend_url\":\"https://localhost:$TP\",\"server_ca_pem\":$CA_JSON,\"admin_email\":\"tina@acme.local\"}" >/dev/null
  tok() { call "$1" POST /api/v1/tenants/acme/tokens "{\"email\":\"$2\",\"name\":\"dev\",\"ttl_days\":30}" | J secret; }
  TINA=$(tok "$ROOT_TOKEN" tina@acme.local)
  call "$TINA" POST /api/v1/tenants/acme/entities '{"slug":"retail","name":"Acme Retail Ltd"}' >/dev/null
  call "$TINA" POST /api/v1/tenants/acme/entities '{"slug":"platform","name":"Acme Platform Ltd"}' >/dev/null
  call "$TINA" POST /api/v1/tenants/acme/bus '{"slug":"payments","name":"Payments","entity":"retail"}' >/dev/null
  call "$TINA" POST /api/v1/tenants/acme/bus '{"slug":"checkout","name":"Checkout","entity":"retail"}' >/dev/null
  call "$TINA" POST /api/v1/tenants/acme/bus '{"slug":"data","name":"Data platform","entity":"platform"}' >/dev/null
  # email:role:scope-kind:scope (scope-kind is bu, entity, or empty for tenant-wide)
  for m in alice@acme.local:developer:bu:payments mike@acme.local:manager:bu:payments rita@acme.local:manager:entity:retail \
           eve@acme.local:developer:bu:data fiona@acme.local:finops:: sam@acme.local:security:: ava@acme.local:auditor::; do
    IFS=: read -r email role kind scope <<<"$m"
    body="{\"email\":\"$email\",\"role\":\"$role\"${kind:+,\"$kind\":\"$scope\"}}"
    call "$TINA" POST /api/v1/tenants/acme/members "$body" >/dev/null
  done
  for f in "$RES"/connections/*.json; do call "$TINA" POST /api/v1/t/acme/connections "@$f" >/dev/null; done
  RUNNER_TOKEN=$(call "$TINA" POST /api/v1/t/acme/runners '{"name":"dev-runner","pool":"default"}' | J secret)
  for f in payments-dev payments-prod data-dev; do call "$TINA" POST /api/v1/t/acme/environments "@$RES/environments/$f.json" >/dev/null; done
  ALICE=$(tok "$TINA" alice@acme.local)
  for f in local-naming prod-naming; do call "$ALICE" POST /api/v1/t/acme/stacks "@$RES/stacks/$f.json" >/dev/null; done
  umask 077
  {
    echo "ROOT=$ROOT_TOKEN       # platform admin (onboarding only)"
    echo "TINA=$TINA       # acme tenant_admin"
    echo "ALICE=$ALICE       # developer, payments"
    for u in mike rita eve fiona sam ava; do echo "$(echo $u | tr a-z A-Z)=$(tok "$TINA" $u@acme.local)"; done
    echo "RUNNER_TOKEN=$RUNNER_TOKEN"
  } >"$DEV/tokens.env"
fi
RUNNER_TOKEN=$(grep '^RUNNER_TOKEN=' "$DEV/tokens.env" | cut -d= -f2)

PRAVAHA_SERVER_URL=https://localhost:$TP PRAVAHA_RUNNER_TOKEN="$RUNNER_TOKEN" PRAVAHA_STATE_KEY="$PRAVAHA_STATE_KEY" \
PRAVAHA_CA_FILE="$C/ca.pem" PRAVAHA_WORK_DIR="$DEV/runs" PRAVAHA_PLUGIN_CACHE_DIR="$DEV/plugin-cache" \
PRAVAHA_CATALOG_DIR="$ROOT/cloud-pravaha-modules/catalog" \
  bin/pravaha runner >"$DEV/runner-acme.log" 2>&1 &
PIDS+=($!)
mkdir -p "$DEV/plugin-cache"

HOOKS="${PRAVAHA_WEBHOOK_BASE_URL:+$PRAVAHA_WEBHOOK_BASE_URL/webhooks/github/acme}"
HOOKS="${HOOKS:-no public URL (run ngrok http $CP before dev-up, or set PRAVAHA_WEBHOOK_BASE_URL)}"
cat <<EOT

  Cloud Pravaha is running at $CENTRAL  (central plane)  ->  tenant acme at https://localhost:$TP
  GitHub webhooks: $HOOKS
  Sign in with a token from $DEV/tokens.env:
    Tenant acme > entities Retail (BUs Payments, Checkout) and Platform (BU Data)
    ALICE  developer, BU Payments: plans stacks      MIKE   manager, BU Payments: signs the manager step
    RITA   manager, entity Retail (all its BUs)      FIONA  finops (tenant): signs finops
    SAM    security (tenant): signs security         EVE    developer, BU Data: cannot see Retail
    AVA    auditor   TINA tenant admin   ROOT platform admin
  Logs in $DEV/*.log.  Ctrl-C to stop (PostgreSQL keeps running: docker rm -f $PG_NAME).

EOT
wait "${PIDS[0]}"
