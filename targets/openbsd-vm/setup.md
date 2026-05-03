# OpenBSD VM target

WireGuard has been part of the OpenBSD base system since OpenBSD 6.8 via the
`wg(4)` driver. No additional packages are required for the WireGuard interface
itself.

## Network configuration

The VM must have a network interface bridged to the host on `192.168.100.0/24`.
Determine the interface name with `ifconfig -a` (commonly `em0` or `vio0`
in QEMU/KVM VMs).

Set a static IP by creating `/etc/hostname.<iface>` (e.g. `/etc/hostname.vio0`):

```
inet 192.168.100.10 xffffff00
```

Set the default gateway in `/etc/mygate`:

```
192.168.100.1
```

Apply without rebooting:

```sh
sh /etc/netstart
```

## WireGuard installation

```sh
pkg_add wireguard-tools
```

## WireGuard configuration

Create the WireGuard interface at boot via `/etc/hostname.wg0`:

```
wgkey yPjffkEFH3SAerBEgKuM1mnp7I2Y5TEb2Y9aKzTmwWU=
wgport 7000
wgpeer PI1mie11niZ+XrprIkYQSKFlMKPasB6J6DsY6UX8ngw= wgaip 10.10.10.1/32
inet 10.10.10.10/24
up
```

Bring it up immediately:

```sh
sh /etc/netstart wg0
```

Verify with `ifconfig wg0` and `wg show`.

## Echo service

Copy `targets/shared/udp_echo.c` to the VM and compile it:

```sh
cc -o udp_echo udp_echo.c
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
virsh -c qemu:///system snapshot-create-as openbsd7.8 openbsd7.8 \
    --description "WireGuard up, echo service running, peer configured"
```

The `reset.sh` script reverts to this snapshot before each test run.
