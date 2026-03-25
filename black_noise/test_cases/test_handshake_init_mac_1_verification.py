"""
Test: verify that the target correctly validates mac1 in handshake initiation packets.

We send two initiations:
  1. A structurally valid initiation with a corrupted mac1 (all-zero).
     The target must silently drop it — no response should arrive.
  2. A correct initiation immediately after.
     The target must respond and complete the handshake.
"""
import socket

from scapy.contrib.wireguard import WireguardInitiation

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget


class TestHandshakeInitMac1Verification(AbstractTestCase):
    """
    We act as the initiator. First we send an initiation with a zeroed mac1
    to verify the target rejects it, then we send a valid one to verify the
    target still processes correct packets afterwards.
    """

    @property
    def name(self) -> str:
        return "mac1_verification_initiator"

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target)

        # --- Step 1: send an initiation with a corrupted (all-zero) mac1 ---
        session = self._new_session(target)
        bad_init_pkt = session.init_handshake(peer_public_key=target.target_public_key)
        bad_init_pkt[WireguardInitiation].mac1 = bytes(16)
        sock.sendto(bytes(bad_init_pkt), (target.target_physical_ip, target.target_wg_port))

        try:
            sock.recvfrom(65535)
            return self._fail(target, "Target responded to an initiation with invalid mac1 — should have been silently dropped")
        except socket.timeout:
            pass  # expected: target dropped the packet

        # --- Step 2: send a valid initiation to confirm the target still works ---
        if report := self._verify_as_initiator(target):
            return report
        return self._pass(target, "Target correctly dropped initiation with invalid mac1 and accepted a valid one")
