# NetBSD VM target

WireGuard support was added to NetBSD as the `wg(4)` driver in NetBSD 9.3.
The `wgconfig(8)` tool (part of the base system) is used to configure it.

## Network configuration

The VM must have a network interface bridged to the host on `192.168.100.0/24`.
Determine the interface name with `ifconfig -a` (commonly `wm0` or `virtio0`
in QEMU/KVM VMs).

Set a static IP by creating `/etc/ifconfig.wm0`:

```
inet 192.168.100.10 netmask 255.255.255.0
```

Set the default gateway in `/etc/mygate`:

```
192.168.100.1
```

Apply without rebooting:

```sh
sh /etc/rc.d/network start
```

## WireGuard configuration

Write the private key to a file:

```sh
echo 'yPjffkEFH3SAerBEgKuM1mnp7I2Y5TEb2Y9aKzTmwWU=' > /etc/wireguard/private.key
chmod 600 /etc/wireguard/private.key
```

Create and configure the interface:

```sh
ifconfig wg0 create
wgconfig wg0 set private-key /etc/wireguard/private.key
wgconfig wg0 set listen-port 7000
wgconfig wg0 add peer server PI1mie11niZ+XrprIkYQSKFlMKPasB6J6DsY6UX8ngw= \
    --allowed-ips=10.10.10.1/32
ifconfig wg0 inet 10.10.10.10/24
ifconfig wg0 up
```

Verify with `ifconfig wg0` and `wgconfig wg0 show`.

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
virsh -c qemu:///system snapshot-create-as netbsd10.1 netbsd10.1 \
    --description "WireGuard up, echo service running, peer configured"
```

The `reset.sh` script reverts to this snapshot before each test run.
