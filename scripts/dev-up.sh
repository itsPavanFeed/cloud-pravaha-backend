#!/usr/bin/env bash
# Local multi-tenant development stack, all on loopback:
#   central plane   http://127.0.0.1:8090   web UI, identity, routing (plain HTTP allowed on loopback only)
#   tenant "acme"   https://localhost:8444  its own database, state and runner; reached by central over mTLS
# Seeds business units (payments, data) and one person per role. Tokens are
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
  call "$TINA" POST /api/v1/tenants/acme/entities '{"slug":"payments","name":"Payments"}' >/dev/null
  call "$TINA" POST /api/v1/tenants/acme/entities '{"slug":"data","name":"Data platform"}' >/dev/null
  for m in alice@acme.local:developer:payments mike@acme.local:manager:payments eve@acme.local:developer:data \
           fiona@acme.local:finops: sam@acme.local:security: ava@acme.local:auditor:; do
    IFS=: read -r email role entity <<<"$m"
    call "$TINA" POST /api/v1/tenants/acme/members "{\"email\":\"$email\",\"role\":\"$role\",\"entity\":\"$entity\"}" >/dev/null
  done
  RUNNER_TOKEN=$(call "$TINA" POST /api/v1/t/acme/runners '{"name":"dev-runner","pool":"default"}' | J secret)
  for f in payments-dev payments-prod data-dev; do call "$TINA" POST /api/v1/t/acme/environments "@$RES/environments/$f.json" >/dev/null; done
  ALICE=$(tok "$TINA" alice@acme.local)
  for f in local-naming prod-naming; do call "$ALICE" POST /api/v1/t/acme/stacks "@$RES/stacks/$f.json" >/dev/null; done
  umask 077
  {
    echo "ROOT=$ROOT_TOKEN       # platform admin (onboarding only)"
    echo "TINA=$TINA       # acme tenant_admin"
    echo "ALICE=$ALICE       # developer, payments"
    for u in mike eve fiona sam ava; do echo "$(echo $u | tr a-z A-Z)=$(tok "$TINA" $u@acme.local)"; done
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

cat <<EOT

  Cloud Pravaha is running at $CENTRAL  (central plane)  ->  tenant acme at https://localhost:$TP
  Sign in with a token from $DEV/tokens.env:
    ALICE  developer in Payments: plans stacks       MIKE   manager in Payments: signs the manager step
    FIONA  finops (whole tenant): signs finops       SAM    security (whole tenant): signs security
    EVE    developer in Data: cannot see Payments    AVA    auditor   TINA tenant admin   ROOT platform admin
  Logs in $DEV/*.log.  Ctrl-C to stop (PostgreSQL keeps running: docker rm -f $PG_NAME).

EOT
wait "${PIDS[0]}"
