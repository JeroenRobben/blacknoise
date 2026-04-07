"""
Test: verify that the target silently drops UDP packets with an unknown
WireGuard message type.

Valid WireGuard message types are 1–4:
  0x01  Handshake Initiation
  0x02  Handshake Response
  0x03  Cookie Reply
  0x04  Transport Data

Any other type byte is outside the spec. A conformant implementation must
drop such packets without sending any response.

We test three variants:
  1. type = 0x00 (reserved/invalid)
  2. type = 0x05 (just above the valid range)
  3. type = 0xFF (max byte value)

The payload after the header is filled with random-looking but fixed bytes so
the packet has a plausible size. After all three are dropped we send a valid
handshake initiation to confirm the target still processes legitimate packets.
"""

from scapy.contrib.wireguard import Wireguard

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget


class TestUnknownMessageType(AbstractTestCase):
    """
    We send three packets with unknown message type bytes and verify the target
    drops each one silently, then confirm it still accepts a valid initiation.
    """

    @property
    def name(self) -> str:
        return "unknown_message_type"

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target)

        # Payload chosen to be the same length as a handshake initiation (148
        # bytes total) so the packet looks plausible in size.
        filler = bytes(range(256)) * 2  # deterministic, non-secret
        payload = filler[:144]          # 4-byte Wireguard header + 144 bytes = 148

        unknown_types = [
            (0x00, "type 0x00 (reserved)"),
            (0x05, "type 0x05 (just above valid range)"),
            (0xFF, "type 0xFF (max byte)"),
        ]

        for msg_type, description in unknown_types:
            pkt = Wireguard(message_type=msg_type, reserved_zero=0) / payload
            sock.sendto(bytes(pkt), (target.target_physical_ip, target.target_wg_port))

            if report := self._expect_silence(sock, target, f"packet with {description}"):
                return report

        if report := self._verify_as_initiator(target):
            return report
        return self._pass(target, "Target correctly dropped all packets with unknown message types and accepted a valid initiation")
