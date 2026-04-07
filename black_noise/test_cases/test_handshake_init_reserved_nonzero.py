"""
Test: verify that the target silently drops handshake initiation messages whose
three reserved bytes are non-zero.

The WireGuard spec defines the first four bytes of every message as:
  u8  message_type
  u8  reserved[3]   (must be 0x00 0x00 0x00)

A conformant implementation should ignore — or ideally reject — messages with
non-zero reserved bytes. We test three variants:

  1. reserved = 0x01 0x00 0x00 (first byte non-zero)
  2. reserved = 0x00 0xFF 0x00 (middle byte non-zero)
  3. reserved = 0xFF 0xFF 0xFF (all bytes non-zero)

Each bad packet is a fully valid initiation (correct mac1, correct crypto) so
the only reason to reject it is the reserved bytes. After all three are dropped
we send a clean initiation to confirm the target still works.
"""

from scapy.contrib.wireguard import Wireguard

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget


class TestHandshakeInitReservedNonzero(AbstractTestCase):
    """
    We act as the initiator. We send three otherwise-valid initiations that
    differ only in their reserved bytes, then confirm the target accepts a
    clean initiation afterwards.
    """

    @property
    def name(self) -> str:
        return "handshake_init_reserved_nonzero"

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target)

        bad_reserved_values = [
            (0x010000, "0x01 0x00 0x00"),
            (0x00FF00, "0x00 0xFF 0x00"),
            (0xFFFFFF, "0xFF 0xFF 0xFF"),
        ]

        for reserved_int, description in bad_reserved_values:
            session = self._new_session(target)
            pkt = session.init_handshake(peer_public_key=target.target_public_key)
            pkt[Wireguard].reserved_zero = reserved_int
            sock.sendto(bytes(pkt), (target.target_physical_ip, target.target_wg_port))

            if report := self._expect_silence(sock, target,
                    f"initiation with reserved bytes {description}"):
                return report

        if report := self._verify_as_initiator(target):
            return report
        return self._pass(target, "Target correctly dropped initiations with non-zero reserved bytes and accepted a valid one")
