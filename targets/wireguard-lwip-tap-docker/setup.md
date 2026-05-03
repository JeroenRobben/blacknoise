# wireguard-lwip-tap-docker target

A WireGuard implementation built on top of lwIP, running inside a Docker
container using a TAP interface. The encrypted WireGuard UDP traffic travels
over a `192.168.1.0/24` TAP segment; the WireGuard tunnel runs on
`10.10.10.0/24`.

The container shares the host network namespace (`--network host`) and is
granted access to `/dev/net/tun` so that lwIP can attach to the existing
`tap0` interface on the host.

## TAP interface setup

Create and configure the `tap0` interface on the host (once per boot):

```sh
sudo ip tuntap add dev tap0 mode tap user $(whoami)
sudo ip addr add 192.168.1.100/24 dev tap0
sudo ip addr add 192.168.1.101/24 dev tap0
sudo ip link set tap0 up
```

`192.168.1.100` is the primary physical address used for WireGuard transport.
`192.168.1.101` is the secondary address used by roaming tests to simulate an
endpoint change.

To remove the interface: `ip tuntap del dev tap0 mode tap`

## Build the Docker image

From the test framework root:

```sh
`docker build -t wireguard-lwip-tap-docker targets/wireguard-lwip-tap-docker/
````

This clones `wireguard-lwip` from GitHub and builds `wg-test` inside the
container using cmake, which fetches lwIP automatically via `FetchContent`.
Only the files in `platform/` are part of this repository; everything else
is fetched at build time.

## Running the target

The `reset.sh` script starts (or restarts) the container:

```sh
targets/wireguard-lwip-tap-docker/reset.sh
```

Logs are available via:

```sh
docker logs wireguard-lwip-tap-docker
```

## Arguments

| Argument | Value | Description |
|---|---|---|
| `wg_private_key` | `iLpnCj7/...` | Target private key |
| `wg_ip` | `10.10.10.10` | WireGuard tunnel IP |
| `peer_pubkey` | `PI1mie11...` | Server (test framework) public key |
| `peer_wg_ip` | `10.10.10.1` | Server WireGuard tunnel IP (allowed IP /32) |
| `peer_endpoint_ip` | `192.168.1.100` | Server's tap0 IP |
| `peer_endpoint_port` | `8000` | Server WireGuard listen port |
| `tap_ip` | `192.168.1.200` | lwIP physical IP on tap0 |
| `tap_gw` | `192.168.1.100` | Default gateway (host tap0 IP) |

`wg-test` does not initiate a handshake on its own; it waits for the test
framework to connect, or triggers one when a UDP probe arrives on the echo
port (9000) from outside the WireGuard subnet. It exposes a UDP echo service
on port `9000` over the WireGuard tunnel.
