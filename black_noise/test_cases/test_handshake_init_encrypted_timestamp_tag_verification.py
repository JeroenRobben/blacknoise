"""
Test: verify that the target checks the AEAD tag of the encrypted_timestamp
field in the handshake initiation message.

In the WireGuard handshake, encrypted_timestamp is:
    AEAD(k, 0, TAI64N_timestamp, h)
The last 16 bytes are the Poly1305 authentication tag. We directly corrupt the
last byte of the tag, making the AEAD decryption fail. The target must reject
the packet.

Because encrypted_timestamp is covered by mac1, we recompute mac1 after the
corruption so the packet is not rejected at the earlier mac1 check and the
target reaches the encrypted_timestamp decryption step.

We then resend the original unaltered initiation to confirm the target still
processes it correctly.
"""
from scapy.contrib.wireguard import Wireguard, WireguardInitiation

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget
from black_noise.state_machine import calc_mac_1



class TestHandshakeInitEncryptedTimestampTagVerification(AbstractTestCase):
    """
    We act as the initiator. We send an initiation with a corrupted Poly1305
    tag in encrypted_timestamp. The target must drop it. Resending the original
    unaltered initiation must succeed.
    """

    @property
    def name(self) -> str:
        return "handshake_init_encrypted_timestamp_tag_verification"

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target)

        session = self._new_session(target)
        init_pkt = session.init_handshake(peer_public_key=target.target_public_key)
        original_pkt_bytes = bytes(init_pkt)

        # Corrupt the last byte of the Poly1305 tag (last 16 bytes of encrypted_timestamp).
        bad_init_pkt = Wireguard(original_pkt_bytes)
        tag = bytearray(bad_init_pkt[WireguardInitiation].encrypted_timestamp)
        tag[-1] ^= 0x01
        bad_init_pkt[WireguardInitiation].encrypted_timestamp = bytes(tag)

        # Recompute mac1 so the packet passes the mac1 check and reaches the
        # encrypted_timestamp decryption step where the invalid AEAD tag will be detected.
        bad_init_pkt[WireguardInitiation].mac1 = calc_mac_1(bad_init_pkt[WireguardInitiation],
                                                             target.target_public_key)

        sock.sendto(bytes(bad_init_pkt), (target.target_physical_ip, target.target_wg_port))

        if report := self._expect_silence(sock, target, "initiation with invalid encrypted_timestamp AEAD tag"):
            return report

        # Confirm the target still processes valid initiations.
        if report := self._verify_as_initiator(target):
            return report
        return self._pass(target, "Target correctly dropped initiation with invalid encrypted_timestamp AEAD tag and accepted the original one")
