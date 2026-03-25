"""
Test: verify that the target rejects handshake initiation messages with an
invalid or insecure ephemeral public key.

Two bad ephemeral keys are tested:

  1. All-zeros (0x00 * 32): the X25519 identity point. A DH with this key
     always produces an all-zeros output, which WireGuard implementations must
     detect and reject.

  2. A low-order point (order 4 on Curve25519, 0xEC FF…FF 7F): a small-subgroup
     point whose DH output cycles through a tiny set of values, making it
     cryptographically weak. Must be rejected.

Each bad initiation is built using a session constructed with a fabricated
ephemeral keypair whose public half is the bad key. This ensures the entire
initiation — including encrypted_static and encrypted_timestamp — is derived
from the bad ephemeral, so the only valid rejection path is ephemeral key
validation rather than a downstream AEAD tag failure.

After both bad packets are dropped we resend the original unaltered initiation
to confirm the target still processes valid packets.
"""
from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget
from black_noise.test_cases.bad_keys import BAD_PUBLIC_KEYS
from black_noise.primitives import wg_dh_generate
from black_noise.state_machine import WgSecureSession



class TestHandshakeInitEphemeralKeyVerification(AbstractTestCase):
    """
    We act as the initiator. For each bad ephemeral key we build a fresh session
    with a fabricated ephemeral keypair whose public half is the bad key, so the
    entire initiation is derived from it. The target must silently drop each one.
    The original unaltered initiation must then succeed.
    """

    @property
    def name(self) -> str:
        return "handshake_init_ephemeral_key_verification"

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target)

        for bad_ephemeral, description in BAD_PUBLIC_KEYS:
            e_priv_fake, _ = wg_dh_generate()
            bad_session = WgSecureSession(
                server_private_key=target.server_private_key,
                preshared_symmetric_key=target.preshared_key or bytes(32),
                ephemeral_keypair=(e_priv_fake, bad_ephemeral),
            )
            bad_session.send_cookie = False
            bad_pkt = bad_session.init_handshake(peer_public_key=target.target_public_key)

            sock.sendto(bytes(bad_pkt), (target.target_physical_ip, target.target_wg_port))

            if report := self._expect_silence(sock, target,
                    f"initiation with {description} ephemeral key"):
                return report

        # --- Valid packet: confirm the target still works ---
        if report := self._verify_as_initiator(target):
            return report
        return self._pass(target, "Target correctly dropped initiations with all-zeros and low-order ephemeral keys, and accepted the original valid one")
