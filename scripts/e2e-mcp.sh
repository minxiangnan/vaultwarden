#!/usr/bin/env bash
# Exercise MCP over HTTP.
#
# Binary:
#   scripts/e2e-mcp.sh
# Docker Compose (builds the production image):
#   VW_DOCKER=1 scripts/e2e-mcp.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ "${VW_DOCKER:-}" == "1" ]]; then
  export ADMIN_TOKEN="${ADMIN_TOKEN:-e2e-admin-token}"
  export DOMAIN="${DOMAIN:-http://127.0.0.1:8080}"
  export SIGNUPS_ALLOWED=true
  export SIGNUPS_VERIFY=false
  export MCP_ENABLED=true
  export WEB_VAULT_ENABLED=false
  export HOST_PORT="${HOST_PORT:-8080}"
  docker compose -f "$ROOT/docker-compose.yml" up -d --build --wait
  export VW_BASE="${VW_BASE:-http://127.0.0.1:${HOST_PORT}}"
  export VW_COMPOSE_FILE="$ROOT/docker-compose.yml"
else
  BIN="${VW_BIN:-$ROOT/target/debug/vaultwarden}"
  DATA="${VW_DATA:-$ROOT/data/e2e-mcp}"
  BASE="${VW_BASE:-http://127.0.0.1:8123}"
  if [[ ! -x "$BIN" ]]; then
    echo "vaultwarden binary not found at $BIN" >&2
    echo "Build it with: cargo build --features sqlite" >&2
    exit 1
  fi
  mkdir -p "$DATA"
  export DATA_FOLDER="$DATA"
  export ROCKET_ADDRESS=127.0.0.1
  export ROCKET_PORT="${ROCKET_PORT:-8123}"
  export DOMAIN="$BASE"
  export SIGNUPS_ALLOWED=true
  export SIGNUPS_VERIFY=false
  export ENABLE_WEBSOCKET=true
  export MCP_ENABLED=true
  export WEB_VAULT_ENABLED=false
  export VW_BASE="$BASE"
  if ! curl -sf "$BASE/alive" >/dev/null 2>&1; then
    nohup "$BIN" >"$DATA/vaultwarden.log" 2>&1 &
    echo $! >"$DATA/vaultwarden.pid"
    disown || true
    ready=0
    for _ in $(seq 1 60); do
      if curl -sf "$BASE/alive" >/dev/null 2>&1; then
        ready=1
        break
      fi
      sleep 0.5
    done
    if [[ "$ready" != 1 ]]; then
      echo "vaultwarden did not become ready" >&2
      tail -n 80 "$DATA/vaultwarden.log" >&2 || true
      exit 1
    fi
  fi
fi

node --test "$ROOT/scripts/mcp-crypto.test.mjs"
node "$ROOT/scripts/e2e-mcp.mjs"
