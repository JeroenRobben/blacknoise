"""
Test: verify that the target checks the AEAD tag of the encrypted_static field
in the handshake initiation message.

In the WireGuard handshake, encrypted_static is:
    AEAD(k, 0, initiator_static_pub, h)
The last 16 bytes are the Poly1305 authentication tag. We directly corrupt one
byte of the tag, making the AEAD decryption fail. The target must reject the packet.

Because encrypted_static is covered by mac1, we recompute mac1 after the
corruption so the packet is not rejected at the earlier mac1 check and the
target reaches the encrypted_static decryption step.

We then send a valid initiation to confirm the target still works correctly.
"""
from scapy.contrib.wireguard import Wireguard, WireguardInitiation

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget
from black_noise.state_machine import calc_mac_1



class TestHandshakeInitEncryptedStaticTagVerification(AbstractTestCase):
    """
    We act as the initiator. We send an initiation with a corrupted Poly1305
    tag in encrypted_static. The target must drop it. A subsequent valid
    initiation must succeed.
    """

    @property
    def name(self) -> str:
        return "handshake_init_encrypted_static_tag_verification"

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target)

        session = self._new_session(target)
        init_pkt = session.init_handshake(peer_public_key=target.target_public_key)
        original_pkt_bytes = bytes(init_pkt)

        # Corrupt the last byte of the Poly1305 tag (last 16 bytes of encrypted_static).
        bad_init_pkt = Wireguard(original_pkt_bytes)
        tag = bytearray(bad_init_pkt[WireguardInitiation].encrypted_static)
        tag[-1] ^= 0x01
        bad_init_pkt[WireguardInitiation].encrypted_static = bytes(tag)

        # Recompute mac1 so the packet passes the mac1 check and reaches the
        # encrypted_static decryption step where the invalid AEAD tag will be detected.
        bad_init_pkt[WireguardInitiation].mac1 = calc_mac_1(bad_init_pkt[WireguardInitiation],
                                                             target.target_public_key)

        sock.sendto(bytes(bad_init_pkt), (target.target_physical_ip, target.target_wg_port))

        if report := self._expect_silence(sock, target, "initiation with invalid encrypted_static AEAD tag"):
            return report

        # Confirm the target still processes valid initiations.
        if report := self._verify_as_initiator(target):
            return report
        return self._pass(target, "Target correctly dropped initiation with invalid encrypted_static AEAD tag and accepted a valid one")
