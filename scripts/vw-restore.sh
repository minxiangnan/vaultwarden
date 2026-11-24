#!/bin/sh
# Restore a backup created by scripts/vw-backup.sh.
# Stops Vaultwarden, replaces the database and files, then starts it again.
#
#   ./scripts/vw-restore.sh backups/vw-20261124T120000Z

set -eu

if [ "${1:-}" = "" ] || [ ! -f "$1/db.sqlite3" ]; then
    echo "Usage: $0 backups/vw-<timestamp>" >&2
    exit 1
fi

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
src=$(CDPATH= cd -- "$1" && pwd)
compose="docker compose -f $root/docker-compose.prod.yml --env-file $root/.env"

$compose stop vaultwarden
$compose run --rm --no-deps --user 0 \
    -v "$src:/restore:ro" \
    --entrypoint sh vaultwarden -c '
        set -eu
        cp /restore/db.sqlite3 /data/db.sqlite3
        rm -f /data/db.sqlite3-wal /data/db.sqlite3-shm
        if [ -s /restore/files.tar.gz ]; then
            tar -C /data -xzf /restore/files.tar.gz
        fi
        chown -R vaultwarden:vaultwarden /data
    '
$compose start vaultwarden
echo "Restored $src"
