#!/bin/sh
set -e

# Create WireGuard interface using the host kernel module
ip link add wg0 type wireguard

# Configure and bring up the interface
wg-quick strip /etc/wireguard/wg0.conf | wg setconf wg0 /dev/stdin
ip addr add 10.10.10.10/24 dev wg0
ip link set wg0 up

# Start the echo service (becomes PID 1 via exec)
exec /usr/local/bin/udp_echo
