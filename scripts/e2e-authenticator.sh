#!/usr/bin/env bash
# Start this fork's vaultwarden for authenticator end-to-end tests and exercise the HTTP API.
#
# The server stays up on http://127.0.0.1:8000 when the script exits, so a browser
# extension can register against it. Re-running the script reuses a server that is
# already answering /alive.
#
#   scripts/e2e-authenticator.sh
#   VW_BIN=/path/to/vaultwarden scripts/e2e-authenticator.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${VW_BIN:-$ROOT/target/debug/vaultwarden}"
DATA="${VW_DATA:-$ROOT/data/e2e-authenticator}"
BASE="${VW_BASE:-http://127.0.0.1:8000}"
EMAIL="${VW_EMAIL:-e2e-$(date +%s)@example.com}"

if [[ ! -x "$BIN" ]]; then
  echo "vaultwarden binary not found at $BIN" >&2
  echo "Build it with: cargo build --features sqlite" >&2
  exit 1
fi

mkdir -p "$DATA"
export DATA_FOLDER="$DATA"
export ROCKET_ADDRESS="${ROCKET_ADDRESS:-127.0.0.1}"
export ROCKET_PORT="${ROCKET_PORT:-8000}"
export DOMAIN="$BASE"
export SIGNUPS_ALLOWED=true
export SIGNUPS_VERIFY=false
export WEB_VAULT_ENABLED=false
# Each logged-in device opens its own /notifications/hub socket. The default is already on;
# set it here so this server cannot be started with realtime sync accidentally disabled.
export ENABLE_WEBSOCKET=true
export LOG_LEVEL="${LOG_LEVEL:-info}"

if ! curl -sf "$BASE/alive" >/dev/null 2>&1; then
  echo "Starting vaultwarden from $BIN"
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
    echo "vaultwarden did not become ready. Log:" >&2
    tail -n 80 "$DATA/vaultwarden.log" >&2 || true
    exit 1
  fi
else
  echo "Reusing vaultwarden already listening on $BASE"
fi

python3 - "$BASE" "$EMAIL" <<'PY'
import json, sys, urllib.error, urllib.request

base, email = sys.argv[1], sys.argv[2]
enc = "2.AAAA|AAAA|AAAA"
enc_b = "2.AAAA|AAAA|AAAB"
enc_c = "2.AAAA|AAAA|AAAC"

def call(method, path, body=None, token=None, form=False, accept="application/json"):
    data = None
    headers = {"Accept": accept, "Bitwarden-Client-Version": "2026.1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        if form:
            from urllib.parse import urlencode
            data = urlencode(body).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw and "json" in resp.headers.get("Content-Type", "") else raw.decode()
    except urllib.error.HTTPError as err:
        detail = err.read().decode()
        raise SystemExit(f"{method} {path} -> {err.code} {detail}") from err

status, token = call(
    "POST",
    "/identity/accounts/register/send-verification-email",
    {"email": email, "name": "E2E"},
)
assert isinstance(token, str) and token, token
print("verification token ok")

_, registered = call(
    "POST",
    "/identity/accounts/register/finish",
    {
        "email": email,
        "name": "E2E",
        "emailVerificationToken": token,
        "masterPasswordHash": "master-hash",
        "masterPasswordHint": None,
        "userSymmetricKey": "2.AAAA|AAAA|AAAA",
        "userAsymmetricKeys": {"publicKey": "pub", "encryptedPrivateKey": "2.AAAA|AAAA|AAAB"},
        "kdf": 0,
        "kdfIterations": 600000,
    },
)
assert registered["object"] == "registerFinish"
print("registered", email)

_, login = call(
    "POST",
    "/identity/connect/token",
    {
        "grant_type": "password",
        "username": email,
        "password": "master-hash",
        "scope": "api offline_access",
        "client_id": "cli",
        "device_identifier": "11111111-1111-1111-1111-111111111111",
        "device_name": "e2e",
        "device_type": "14",
    },
    form=True,
)
access = login["access_token"]
print("logged in")

_, created = call(
    "POST",
    "/api/authenticator",
    {"name": enc, "secret": enc_b, "issuer": enc_c, "algorithm": "SHA256", "digits": 8, "period": 60, "favorite": True, "sortOrder": 3},
    token=access,
)
assert created["object"] == "authenticatorEntry"
assert created["secret"] == enc_b
entry_id = created["id"]
print("created", entry_id)

_, listed = call("GET", "/api/authenticator", token=access)
assert listed["object"] == "list" and listed["continuationToken"] is None
assert len(listed["data"]) == 1 and listed["data"][0]["id"] == entry_id
print("listed")

_, updated = call(
    "PUT",
    f"/api/authenticator/{entry_id}",
    {"name": enc_c, "secret": enc, "algorithm": "SHA1", "digits": 6, "period": 30, "favorite": False, "sortOrder": 1},
    token=access,
)
assert updated["name"] == enc_c and updated["issuer"] is None and updated["algorithm"] == "SHA1"
print("updated")

_, sync = call("GET", "/api/sync", token=access)
item = sync["authenticatorEntries"][0]
for key in ("id", "name", "issuer", "secret", "algorithm", "digits", "period", "notes", "favorite", "sortOrder", "revisionDate", "creationDate", "object"):
    assert key in item, key
assert item["object"] == "authenticatorEntry"
assert sync["authenticatorKeyRotation"]["required"] is False
print("sync shape ok")

status, _ = call("DELETE", f"/api/authenticator/{entry_id}", token=access, accept="*/*")
assert status == 200
_, listed = call("GET", "/api/authenticator", token=access)
assert listed["data"] == []
print("deleted")

# Recreate, then rotate the account key with the entry in the same request.
_, created = call("POST", "/api/authenticator", {"name": enc, "secret": enc_b}, token=access)
entry_id = created["id"]
_, rotated = call(
    "POST",
    "/api/accounts/key-management/rotate-user-account-keys",
    {
        "oldMasterKeyAuthenticationHash": "master-hash",
        "accountKeys": {
            "userKeyEncryptedAccountPrivateKey": "2.AAAA|AAAA|AAAD",
            "accountPublicKey": "pub",
        },
        "accountUnlockData": {
            "masterPasswordUnlockData": {
                "kdfType": 0,
                "iterations": 600000,
                "email": email,
                "masterKeyAuthenticationHash": "new-master-hash",
                "masterKeyEncryptedUserKey": "2.AAAA|AAAA|AAAE",
            },
            "emergencyAccessUnlockData": [],
            "organizationAccountRecoveryUnlockData": [],
            "passkeyUnlockData": [],
            "deviceKeyUnlockData": [],
        },
        "accountData": {
            "ciphers": [],
            "folders": [],
            "sends": [],
            "authenticatorEntries": [{
                "id": entry_id,
                "name": enc_c,
                "secret": enc,
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30,
                "favorite": False,
                "sortOrder": 0,
            }],
        },
    },
    token=access,
    accept="*/*",
)
print("password rotation with authenticatorEntries ok")

_, login = call(
    "POST",
    "/identity/connect/token",
    {
        "grant_type": "password",
        "username": email,
        "password": "new-master-hash",
        "scope": "api offline_access",
        "client_id": "cli",
        "device_identifier": "22222222-2222-2222-2222-222222222222",
        "device_name": "e2e-2",
        "device_type": "14",
    },
    form=True,
)
access = login["access_token"]
_, sync = call("GET", "/api/sync", token=access)
assert sync["authenticatorEntries"][0]["secret"] == enc
assert sync["authenticatorEntries"][0]["name"] == enc_c
assert sync["authenticatorKeyRotation"]["required"] is False
print("post-rotation sync ok")
print("API e2e passed")
PY

echo "vaultwarden is listening at $BASE"
echo "stop it with: kill \$(cat $DATA/vaultwarden.pid)"
