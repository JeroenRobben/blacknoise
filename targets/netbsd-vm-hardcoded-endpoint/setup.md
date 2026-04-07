# NetBSD VM target — hardcoded endpoint

Follow `../netbsd-vm-no-endpoint/setup.md` for the full setup. The only
difference is adding `--endpoint` to the `wgconfig add-peer` command:

```sh
wgconfig wg0 add peer server PI1mie11niZ+XrprIkYQSKFlMKPasB6J6DsY6UX8ngw= \
    --allowed-ips=10.10.10.1/32 \
    --endpoint=192.168.100.1:8000
```
**Snapshot name:**

```sh
virsh -c qemu:///system snapshot-create-as netbsd netbsd-hardcoded-endpoint \
    --description "WireGuard up, echo service running, peer endpoint hardcoded"
```
