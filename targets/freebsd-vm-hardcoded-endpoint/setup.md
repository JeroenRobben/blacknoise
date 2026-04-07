# FreeBSD VM target — hardcoded endpoint

Follow `../freebsd-vm-no-endpoint/setup.md` for the full setup. The only
difference is adding `Endpoint` to the peer section in
`/usr/local/etc/wireguard/wg0.conf`:

```ini
[Peer]
PublicKey = PI1mie11niZ+XrprIkYQSKFlMKPasB6J6DsY6UX8ngw=
AllowedIPs = 10.10.10.1/32
Endpoint = 192.168.100.1:8000
```

**Snapshot name:**

```sh
virsh -c qemu:///system snapshot-create-as freebsd freebsd-hardcoded-endpoint \
    --description "WireGuard up, echo service running, peer endpoint hardcoded"
```
