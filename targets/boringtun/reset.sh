#!/usr/bin/env bash
set -e
DIR="$(dirname "$0")"

docker compose -f "$DIR/docker-compose.yml" up -d --force-recreate

# Add the second host IP to the bridge for roaming tests (ignore error if already present)
sudo ip addr add 192.168.100.2/24 dev wg-test-br 2>/dev/null || true

# Verify the IP is present
if ! ip addr show wg-test-br | grep -q "192.168.100.2"; then
    echo "ERROR: failed to add 192.168.100.2 to wg-test-br" >&2
    exit 1
fi
