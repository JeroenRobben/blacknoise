$port        = 9000
$replyIp     = "10.10.10.1"
$listener    = [System.Net.Sockets.UdpClient]::new($port)
$replyTarget = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($replyIp), $port)

New-NetFirewallRule -DisplayName "UDP Echo $port" -Direction Inbound -Protocol UDP -LocalPort 9000 -Action Allow
Write-Host "$(Get-Date -f 'HH:mm:ss.fff') [START] Listening on 0.0.0.0:$port, forwarding to ${replyIp}:${port}"

try {
    while ($true) {
        $from = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $data = $listener.Receive([ref]$from)
        $ts   = Get-Date -Format 'HH:mm:ss.fff'
        Write-Host "$ts [RECV] $($from.Address):$($from.Port) -> $($data.Length) bytes"
        $sent = $listener.Send($data, $data.Length, $replyTarget)
        Write-Host "$ts [SEND] -> ${replyIp}:${port} $sent bytes"
    }
} catch {
    Write-Host "$(Get-Date -f 'HH:mm:ss.fff') [ERROR] $_"
} finally {
    $listener.Close()
    Write-Host "$(Get-Date -f 'HH:mm:ss.fff') [STOP] Listener closed"
}