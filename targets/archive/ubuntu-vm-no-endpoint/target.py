import base64
import os

from black_noise.TestTarget import TestTarget

_DIR = os.path.dirname(__file__)

target = TestTarget(
    name="ubuntu-vm-no-endpoint",
    reset_script=os.path.join(_DIR, "reset.sh"),

    # Physical network (host ↔ VM)
    target_physical_ip="192.168.100.10",
    target_wg_port=7000,
    server_physical_ip_1="192.168.100.1",
    server_physical_ip_2="192.168.100.2",

    # WireGuard keys — target private key: yPjffkEFH3SAerBEgKuM1mnp7I2Y5TEb2Y9aKzTmwWU=
    target_public_key=base64.b64decode("T6RSDuZEb5VY0q7BWbK0wgF9ltThMpcLesoWOfkQ4Xk="),

    # Server (our side) — from targets/server.conf
    server_private_key=base64.b64decode("sOrI0RWLJAVbczm0jOrPSMTzJ8tGGbPNXrCesFeGtkI="),
    server_wg_port=8000,

    # WireGuard tunnel addresses
    server_wg_ip="10.10.10.1",
    target_wg_ip="10.10.10.10",

    # UDP echo service port (udp_echo.c LISTEN_PORT)
    echo_port=9000,

    preshared_key=None,
)
