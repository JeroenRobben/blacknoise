# FreeBSD VM target

FreeBSD 13.0 and later include WireGuard as the `if_wg` kernel module.
The `wireguard-tools` package provides `wg` and `wg-quick` for configuration.

## Network configuration

The VM must have a network interface bridged to the host on `192.168.100.0/24`.
Determine the interface name with `ifconfig -a` (commonly `em0` or `vtnet0`
in QEMU/KVM VMs).

Add the following to `/etc/rc.conf`:

```
ifconfig_vtnet0="inet 192.168.100.10 netmask 255.255.255.0"
defaultrouter="192.168.100.1"
```

Configure nameservers by adding the following to `/etc/resolv.conf`:
```
nameserver="8.8.8.8"
nameserver="1.1.1.1"
```

Optionally, make resolv.conf immutable so your changes persist across reboots:
```
chflags schg /etc/resolv.conf
```

Apply without rebooting:

```sh
service netif restart && service routing restart
```

## WireGuard installation

```sh
pkg install wireguard-tools
```

## WireGuard configuration

Create the configuration directory and copy `targets/shared/wg0.conf` from the
test framework to `/usr/local/etc/wireguard/wg0.conf` on the VM:

```sh
mkdir -p /usr/local/etc/wireguard
```

Optionally, enable the interface at boot by adding to `/etc/rc.conf`:

```
wireguard_interfaces="wg0"
```

Bring it up immediately:

```sh
wg-quick up wg0
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
virsh -c qemu:///system snapshot-create-as freebsd15.0 freebsd15.0 \
    --description "WireGuard up, echo service running, peer configured"
```

The `reset.sh` script reverts to this snapshot before each test run.
