#!/bin/sh
set -e

# Start gotatun in the background (creates the wg0 TUN interface)
gotatun wg0 --disable-drop-privileges &

# Wait for the interface to appear
for i in $(seq 1 20); do
    ip link show wg0 >/dev/null 2>&1 && break
    sleep 0.5
done

# Configure and bring up the WireGuard interface
wg setconf wg0 /etc/wireguard/wg0.conf
ip addr add 10.10.10.10/24 dev wg0
ip link set wg0 up

# Start the echo service (becomes PID 1 via exec)
exec /usr/local/bin/udp_echo
