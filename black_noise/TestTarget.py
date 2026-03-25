from dataclasses import dataclass


@dataclass
class TestTarget:
    """
    Describes a WireGuard implementation under test.

    name:                 Human-readable name for this target, used in test output.

    reset_script:         Path to an executable script that resets the target to a
                          known-good state before each test run. It receives no
                          arguments; all configuration should be baked into the script.

    teardown_script:      Optional path to an executable script run once after all tests
                          complete. Use this to stop services started by reset_script
                          (e.g. stopping a Docker container).

    target_physical_ip:   Physical IP address of the target (the "internet" address
                          WireGuard UDP packets are sent to).
    server_physical_ip_1: First physical IP address of the test host. Used as the
                          default source address for WireGuard UDP packets.
    server_physical_ip_2: Second physical IP address of the test host. Used by
                          roaming tests to simulate an endpoint change.

    target_public_key:    The target's WireGuard public key (32 bytes).
    server_private_key:   The test host's WireGuard private key (32 bytes).

    server_wg_ip:         The test host's IP address inside the WireGuard tunnel.
    server_wg_port:       The UDP port the test host listens on for WireGuard traffic.
    target_wg_ip:         The target's IP address inside the WireGuard tunnel.
    target_wg_port:       The UDP port the target listens on for WireGuard traffic.

    echo_port:            UDP port of the echo service running on the target.
                          The echo service listens on all interfaces and replies
                          to server_wg_ip through the WireGuard tunnel.

    preshared_key:        Optional 32-byte pre-shared key for the WireGuard session.
    """
    name: str
    reset_script: str

    target_physical_ip: str
    server_physical_ip_1: str
    server_physical_ip_2: str
    target_public_key: bytes

    server_private_key: bytes

    server_wg_ip: str
    server_wg_port: int
    target_wg_ip: str
    target_wg_port: int
    echo_port: int


    preshared_key: bytes | None = None
    teardown_script: str | None = None

