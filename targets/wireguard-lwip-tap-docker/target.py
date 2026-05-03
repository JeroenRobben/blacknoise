import base64
import os

from black_noise.TestTarget import TestTarget

_DIR = os.path.dirname(__file__)

# Target private key: iLpnCj7/xl8/iwnQlqF95bLpGUUQp8Peed14nGgtMFA=
# Server (test framework) private key: sOrI0RWLJAVbczm0jOrPSMTzJ8tGGbPNXrCesFeGtkI=
# Server public key:  PI1mie11niZ+XrprIkYQSKFlMKPasB6J6DsY6UX8ngw=

target = TestTarget(
    name="wireguard-lwip-tap-docker",
    reset_script=os.path.join(_DIR, "reset.sh"),
    teardown_script=os.path.join(_DIR, "teardown.sh"),

    # tap0 on the host is at 192.168.1.100/24.
    # lwIP uses 192.168.1.200 (different IP so the kernel routes through tap0).
    # Encrypted WireGuard UDP goes over this 192.168.1.0/24 segment.
    target_physical_ip="192.168.1.200",
    target_wg_port=51820,
    server_physical_ip_1="192.168.1.100",   # host tap0 IP
    server_physical_ip_2="192.168.1.101",   # host tap0 secondary IP (bindable; for roaming tests)

    target_public_key=base64.b64decode("5Z2sX+tOTegtYj9oh+jWohqWy7hc4zKQ/VdlnLuU+z0="),
    server_private_key=base64.b64decode("sOrI0RWLJAVbczm0jOrPSMTzJ8tGGbPNXrCesFeGtkI="),
    server_wg_port=8000,

    server_wg_ip="10.10.10.1",
    target_wg_ip="10.10.10.10",

    echo_port=9000,

    preshared_key=None,

    capture_interface="tap0",
)
