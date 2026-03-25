# UDP echo: listens on all interfaces port $port, sends payload to $replyIp:$port

$port  = 9000
$replyIp     = "10.10.10.1"

$listener    = [System.Net.Sockets.UdpClient]::new($port)
$replyTarget = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($replyIp), $port)

Write-Host "Listening on 0.0.0.0:$port, forwarding payloads to ${replyIp}:${port}"

try {
    while ($true) {
        $from = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $data = $listener.Receive([ref]$from)
        $listener.Send($data, $data.Length, $replyTarget) | Out-Null
    }
} finally {
    $listener.Close()
}
