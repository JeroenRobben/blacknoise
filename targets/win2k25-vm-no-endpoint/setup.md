# Windows Server 2025 VM target — no endpoint

Tested with Windows Server 2025. A free evaluation copy is available at
https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025

Uses the official WireGuard for Windows client. The echo service is implemented
in PowerShell (`udp_echo.ps1`).

## Network configuration

The VM must have a network interface bridged to the host on `192.168.100.0/24`.

Set a static IP via PowerShell (run as Administrator). Adjust the interface
name as shown by `Get-NetAdapter`:

```powershell
$iface = "Ethernet"
New-NetIPAddress -InterfaceAlias $iface -IPAddress 192.168.100.10 -PrefixLength 24 -DefaultGateway 192.168.100.1
```

## WireGuard installation

Download and install the WireGuard for Windows MSI from
[wireguard.com/install](https://www.wireguard.com/install/).

## WireGuard configuration

Open the WireGuard GUI and click **Add Tunnel → Import tunnel(s) from file...**, then import `wg0.conf`.

Click **Activate** to bring the tunnel up.

## Echo service

### Firewall
Configure the Firewall to allow incoming UDP packets on port 9000, and ping requests for the config check.

```cmd
New-NetFirewallRule -DisplayName "UDP Echo 9000" -Direction Inbound -Protocol UDP -LocalPort 9000 -Action Allow
Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In
Enable-NetFirewallRule -Name FPS-ICMP6-ERQ-In
```

### Script
Copy `targets/shared/udp_echo.ps1` to the VM. Run it in a PowerShell window
(after the WireGuard tunnel is active):

```powershell
powershell -ExecutionPolicy Bypass -File udp_echo.ps1
```

The echo service listens on `0.0.0.0:9000` and forwards received payloads to
`10.10.10.1:9000` over the WireGuard tunnel.

To run it automatically at startup, create a scheduled task that runs the
script at logon (with the WireGuard tunnel already active).

## Taking the snapshot

With the WireGuard tunnel active and the echo service running, take a snapshot
from the host:

```sh
virsh -c qemu:///system snapshot-create-as win2k25 win2k25-no-endpoint \
    --description "WireGuard up, echo service running, no peer endpoint"`
```

The `reset.sh` script reverts to this snapshot before each test run.
