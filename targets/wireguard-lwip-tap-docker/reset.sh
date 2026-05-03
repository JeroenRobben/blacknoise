#!/usr/bin/env bash
set -e

# Kill any existing container
docker rm -f wireguard-lwip-tap-docker 2>/dev/null || true
sleep 0.3

# Run the container:
#   --network host       shares the host network namespace so the container
#                        sees tap0 and can bind to 192.168.1.200
#   --device /dev/net/tun  grants access to open the TUN/TAP device node
#   --cap-add=NET_ADMIN  lets the container attach to tap0 via TUNSETIFF
#                        (the persistent tap is owned by a non-root uid on the host)
#   -e PRECONFIGURED_TAPIF  tells lwIP's tapif to attach to an existing tap0
#                           instead of creating a new one
docker run -d --name wireguard-lwip-tap-docker \
    --network host \
    --device /dev/net/tun \
    --cap-add=NET_ADMIN \
    -e PRECONFIGURED_TAPIF=tap0 \
    wireguard-lwip-tap-docker \
    "iLpnCj7/xl8/iwnQlqF95bLpGUUQp8Peed14nGgtMFA=" "10.10.10.10" \
    "PI1mie11niZ+XrprIkYQSKFlMKPasB6J6DsY6UX8ngw=" "10.10.10.1" \
    "192.168.1.100" 8000 \
    "192.168.1.200" "192.168.1.100"

# Wait for lwIP to initialise and the TAP interface to come up
sleep 1
