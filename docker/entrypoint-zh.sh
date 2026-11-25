#!/bin/sh
# Start as root only to make the data volume writable, then run the server as uid 1000.
set -eu

if [ "$(id -u)" = "0" ]; then
    chown vaultwarden:vaultwarden /data
    exec runuser -u vaultwarden -- /vaultwarden "$@"
fi

exec /vaultwarden "$@"
