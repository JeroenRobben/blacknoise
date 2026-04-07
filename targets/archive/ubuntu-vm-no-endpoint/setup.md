# Ubuntu VM target — no endpoint

Uses the Linux kernel WireGuard implementation (`wireguard` module), available
in the kernel since 5.6 and backported to Ubuntu's kernels.

## Network configuration

The VM must have a network interface bridged to the host on `192.168.100.0/24`.
Determine the interface name with `ip link` (commonly `enp1s0` or `ens3` in
QEMU/KVM VMs).

Set a static IP by editing `/etc/netplan/01-netcfg.yaml` (adjust the interface
name as needed):

```yaml
network:
  version: 2
  ethernets:
    enp1s0:
      addresses: [192.168.100.10/24]
      routes:
        - to: default
          via: 192.168.100.1
```

Apply:

```sh
netplan apply
```

## WireGuard installation

```sh
apt install wireguard-tools
```

## WireGuard configuration

Write the configuration to `/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address = 10.10.10.10/24
ListenPort = 7000
PrivateKey = yPjffkEFH3SAerBEgKuM1mnp7I2Y5TEb2Y9aKzTmwWU=

[Peer]
PublicKey = PI1mie11niZ+XrprIkYQSKFlMKPasB6J6DsY6UX8ngw=
AllowedIPs = 10.10.10.1/32
```

Bring the interface up:

```sh
wg-quick up wg0
```

Enable at boot:

```sh
systemctl enable wg-quick@wg0
```

Verify with `wg show`.

## Echo service

Copy `targets/shared/udp_echo.c` to the VM and compile it:

```sh
gcc -o udp_echo udp_echo.c
```

Run it in the background (after the WireGuard interface is up):

```sh
./udp_echo &
```

The echo service listens on `0.0.0.0:9000` and forwards received payloads to
`10.10.10.1:9000` over the WireGuard tunnel.

## Taking the snapshot

With the WireGuard interface up and the echo service running, take a snapshot
from the host:

```sh
virsh -c qemu:///system snapshot-create-as ubuntu25.10 ubuntu-client-no-endpoint \
    --description "WireGuard up, echo service running, no peer endpoint"
```

The `reset.sh` script reverts to this snapshot before each test run.
