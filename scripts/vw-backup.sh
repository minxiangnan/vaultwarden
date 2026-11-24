#!/bin/sh
# Online SQLite backup plus attachments, the RSA key, and config.json.
# The server stays up. `.backup` is a consistent snapshot; copying the live
# db.sqlite3 file is not.
#
#   ./scripts/vw-backup.sh
#   ./scripts/vw-backup.sh /var/backups/vaultwarden
#
# Copy the result off the VPS. This script refuses to run when DATABASE_URL
# is Postgres or MySQL.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
compose="docker compose -f $root/docker-compose.prod.yml --env-file $root/.env"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out=${1:-$root/backups/vw-$stamp}

db_url=$($compose exec -T vaultwarden printenv DATABASE_URL 2>/dev/null || true)
case $db_url in
    mysql:*|postgresql:*|postgres:*)
        echo "This data directory is not SQLite ($db_url)." >&2
        echo "Use pg_dump or mysqldump. See docs/zh-production.md." >&2
        exit 1
        ;;
esac

mkdir -p "$out"
$compose exec -T vaultwarden sqlite3 /data/db.sqlite3 ".backup '/tmp/vaultwarden-backup.sqlite3'"
$compose cp vaultwarden:/tmp/vaultwarden-backup.sqlite3 "$out/db.sqlite3"
$compose exec -T vaultwarden rm -f /tmp/vaultwarden-backup.sqlite3

# Missing directories are skipped. tar still fails if nothing at all exists.
$compose exec -T vaultwarden sh -c '
    set --
    for name in attachments sends rsa_key.pem config.json; do
        if [ -e "/data/$name" ]; then
            set -- "$@" "$name"
        fi
    done
    if [ "$#" -eq 0 ]; then
        exit 0
    fi
    tar -C /data -czf - "$@"
' > "$out/files.tar.gz"

echo "Wrote $out"
echo "Keep this directory offline. It can unlock the vault only together with each user's master password."
