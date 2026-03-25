"""
Test: verify that the target checks the AEAD tag of the encrypted_nothing field
in the handshake response message.

In the WireGuard handshake, encrypted_nothing is:
    AEAD(k, 0, "", h)
The last 16 bytes are the Poly1305 authentication tag. We directly corrupt the
last byte of the tag, making the AEAD decryption fail. The target (acting as
initiator) must reject the response.

Because encrypted_nothing is covered by mac1, we recompute mac1 after the
corruption so the response is not rejected at the earlier mac1 check and the
target reaches the encrypted_nothing decryption step where the invalid tag will
be detected.

We then confirm the target still processes a valid response correctly.
"""
import socket

from scapy.contrib.wireguard import Wireguard, WireguardResponse, WireguardTransport

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget
from black_noise.state_machine import calc_mac_1



class TestHandshakeResponseEncryptedNothingTagVerification(AbstractTestCase):
    """
    We act as the responder. We send a handshake response with a corrupted
    Poly1305 tag in encrypted_nothing. The target must drop it. A subsequent
    valid handshake must succeed.
    """

    @property
    def name(self) -> str:
        return "handshake_response_encrypted_nothing_tag_verification"

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target)

        session = self._new_session(target)
        self._probe(target)

        try:
            pkt_bytes, target_addr = sock.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, "Target did not send a handshake initiation")

        init_pkt = Wireguard(pkt_bytes)
        if init_pkt.message_type != 1:
            return self._fail(target, f"Expected handshake initiation (type 1), got type {init_pkt.message_type}")

        bad_response = session.handle_packet(init_pkt)

        # Corrupt the last byte of the Poly1305 tag (last 16 bytes of encrypted_nothing).
        tag = bytearray(bad_response[WireguardResponse].encrypted_nothing)
        tag[-1] ^= 0x01
        bad_response[WireguardResponse].encrypted_nothing = bytes(tag)

        # Recompute mac1 so the response passes the mac1 check and reaches the
        # encrypted_nothing decryption step where the invalid AEAD tag will be detected.
        bad_response[WireguardResponse].mac1 = calc_mac_1(bad_response[WireguardResponse],
                                                           target.target_public_key)

        sock.sendto(bytes(bad_response), target_addr)

        # Drain until timeout. Any transport packet means the target accepted the
        # bad response — that is a failure.
        while True:
            try:
                pkt_bytes, _ = sock.recvfrom(65535)
                if isinstance(Wireguard(pkt_bytes).payload, WireguardTransport):
                    return self._fail(target, "Target completed handshake with a response carrying an invalid encrypted_nothing AEAD tag")
            except socket.timeout:
                break

        if report := self._verify_as_responder(target):
            return report
        return self._pass(target, "Target correctly dropped response with invalid encrypted_nothing AEAD tag and accepted a valid one")
