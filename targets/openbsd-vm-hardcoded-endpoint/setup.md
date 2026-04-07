# OpenBSD VM target — hardcoded endpoint

Follow `../openbsd-vm-no-endpoint/setup.md` for the full setup. The only
differences are:

**`/etc/hostname.wg0`** — add `wgendpoint` to the peer line:

```
wgkey yPjffkEFH3SAerBEgKuM1mnp7I2Y5TEb2Y9aKzTmwWU=
wgport 7000
wgpeer PI1mie11niZ+XrprIkYQSKFlMKPasB6J6DsY6UX8ngw= wgendpoint 192.168.100.1 8000 wgaip 10.10.10.1/32
inet 10.10.10.10/24
up
```

**Snapshot name:**

```sh
virsh -c qemu:///system snapshot-create-as openbsd openbsd-hardcoded-endpoint \
    --description "WireGuard up, echo service running, peer endpoint hardcoded"
```
