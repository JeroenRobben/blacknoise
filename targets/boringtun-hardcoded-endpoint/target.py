import base64
import os

from black_noise.TestTarget import TestTarget

_DIR = os.path.dirname(__file__)

target = TestTarget(
    name="boringtun-hardcoded-endpoint",
    reset_script=os.path.join(_DIR, "reset.sh"),
    teardown_script=os.path.join(_DIR, "teardown.sh"),

    target_physical_ip="192.168.100.10",
    target_wg_port=7000,
    server_physical_ip_1="192.168.100.1",
    server_physical_ip_2="192.168.100.2",

    target_public_key=base64.b64decode("T6RSDuZEb5VY0q7BWbK0wgF9ltThMpcLesoWOfkQ4Xk="),
    server_private_key=base64.b64decode("sOrI0RWLJAVbczm0jOrPSMTzJ8tGGbPNXrCesFeGtkI="),
    server_wg_port=8000,

    server_wg_ip="10.10.10.1",
    target_wg_ip="10.10.10.10",

    echo_port=9000,

    preshared_key=None,
)
