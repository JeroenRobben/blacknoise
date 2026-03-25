"""
Test: verify that the target rejects handshake initiation messages where the
decrypted encrypted_static field contains an invalid or insecure static public key.

Two bad static keys are tested:

  1. All-zeros (0x00 * 32): the X25519 identity point. A DH with this key
     always produces an all-zeros output, which WireGuard implementations must
     detect and reject.

  2. A low-order point (order 4 on Curve25519, 0xEC FF…FF 7F): a small-subgroup
     point whose DH output cycles through a tiny set of values, making it
     cryptographically weak. Must be rejected.

To produce a packet where encrypted_static decrypts to a bad key, we construct
the initiation using a session whose server_public_key is overridden to the bad
key before calling init_handshake. This keeps the AEAD tag and mac1 both valid
so the target reaches the decrypted-key validation step rather than rejecting
earlier due to a tag or MAC failure.

After both bad packets are dropped we send a fresh valid initiation to confirm
the target still processes valid packets.
"""
from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget
from black_noise.test_cases.bad_keys import BAD_PUBLIC_KEYS



class TestHandshakeInitEncryptedStaticKeyVerification(AbstractTestCase):
    """
    We act as the initiator. We send initiations whose encrypted_static field
    decrypts to a known-bad static public key. The target must drop each one.
    A subsequent valid initiation must succeed.
    """

    @property
    def name(self) -> str:
        return "handshake_init_encrypted_static_key_verification"

    def _make_init_with_bad_static(self, target: TestTarget, bad_key: bytes) -> bytes:
        """Build a handshake initiation whose encrypted_static decrypts to bad_key."""
        session = self._new_session(target)
        session.server_public_key = bad_key
        pkt = session.init_handshake(peer_public_key=target.target_public_key)
        return bytes(pkt)

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target)

        for bad_key, description in BAD_PUBLIC_KEYS:
            bad_pkt_bytes = self._make_init_with_bad_static(target, bad_key)
            sock.sendto(bad_pkt_bytes, (target.target_physical_ip, target.target_wg_port))

            if report := self._expect_silence(sock, target,
                    f"initiation with encrypted_static decrypting to {description}"):
                return report

        # --- Valid packet: confirm the target still works ---
        if report := self._verify_as_initiator(target):
            return report
        return self._pass(target, "Target correctly dropped initiations with all-zeros and low-order decrypted static keys, and accepted a valid one")
