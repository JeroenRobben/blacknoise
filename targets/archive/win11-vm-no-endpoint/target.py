import base64
import os

from black_noise.TestTarget import TestTarget

_DIR = os.path.dirname(__file__)

target = TestTarget(
    name="win11-vm-no-endpoint",
    reset_script=os.path.join(_DIR, "reset.sh"),  # TODO: create reset.sh

    # Physical network (host ↔ VM)
    target_physical_ip="TODO",  # TODO: set VM IP
    target_wg_port=7000,  # TODO: confirm WireGuard listen port
    server_physical_ip_1="192.168.100.1",
    server_physical_ip_2="192.168.100.2",

    # WireGuard keys — TODO: fill in after generating wg.conf for this target
    target_public_key=base64.b64decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),

    # Server (our side) — from targets/server.conf
    server_private_key=base64.b64decode("sOrI0RWLJAVbczm0jOrPSMTzJ8tGGbPNXrCesFeGtkI="),
    server_wg_port=8000,

    # WireGuard tunnel addresses
    server_wg_ip="10.10.10.1",
    target_wg_ip="10.10.10.10",  # TODO: confirm

    # UDP echo service port (udp_echo.ps1 $listenPort)
    echo_port=9000,

    preshared_key=None,
)
