"""
Test: verify that the target (acting as initiator) correctly validates mac1 in
handshake response packets.

We act as the responder. We trigger the target to initiate a handshake, then
send back a structurally valid response with a corrupted (all-zero) mac1.
The target must silently drop it. We then trigger a fresh handshake and send a
correct response to confirm the target still works properly.
"""
import socket

from scapy.contrib.wireguard import Wireguard, WireguardInitiation, WireguardResponse, WireguardTransport
from scapy.packet import Raw

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget

RETRANSMIT_TIMEOUT = 7.0


class TestHandshakeResponseMac1Verification(AbstractTestCase):
    """
    We act as the responder. We send a handshake response with a zeroed mac1
    to verify the target rejects it, then complete a valid handshake to confirm
    the target recovers and still processes correct responses.
    """

    @property
    def name(self) -> str:
        return "mac1_verification_responder"

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target)

        # --- Phase 1: send a response with corrupted mac1 ---
        session1 = self._new_session(target)
        self._probe(target)

        try:
            pkt_bytes, target_addr = sock.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, "Did not receive handshake initiation within 3 seconds")

        bad_response = session1.handle_packet(Wireguard(pkt_bytes))
        if bad_response is None:
            return self._fail(target, "Failed to process handshake initiation")

        bad_response[WireguardResponse].mac1 = bytes(16)
        sock.sendto(bytes(bad_response), target_addr)

        # Drain packets for the timeout window. Any transport packet means the
        # target accepted the bad response — that is a failure.
        while True:
            try:
                pkt_bytes, _ = sock.recvfrom(65535)
                if isinstance(Wireguard(pkt_bytes).payload, WireguardTransport):
                    return self._fail(target, "Target completed handshake with a response carrying invalid mac1")
                # Retransmitted initiation or other non-transport packet: keep draining.
            except socket.timeout:
                break

        # --- Phase 2: trigger a fresh handshake and send a valid response ---
        session2 = self._new_session(target)
        self._probe(target)

        sock.settimeout(RETRANSMIT_TIMEOUT)
        while True:
            try:
                pkt_bytes, init_addr = sock.recvfrom(65535)
            except socket.timeout:
                return self._fail(target, "Did not receive a new handshake initiation for the valid-response phase")
            if isinstance(Wireguard(pkt_bytes).payload, WireguardInitiation):
                break
            # Stray packet (e.g. late retransmit of old session): skip it.

        good_response = session2.handle_packet(Wireguard(pkt_bytes))
        if good_response is None:
            return self._fail(target, "Failed to process handshake initiation in valid-response phase")

        sock.sendto(bytes(good_response), init_addr)

        sock.settimeout(3.0)
        try:
            pkt_bytes, _ = sock.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, "Target did not send any packet after a valid handshake response")

        first_result = session2.handle_packet(Wireguard(pkt_bytes))

        if first_result is None:
            # Keepalive — wait for the echo reply.
            try:
                pkt_bytes, _ = sock.recvfrom(65535)
            except socket.timeout:
                return self._fail(target, "Received keepalive but no echo reply followed within 3 seconds")
            first_result = session2.handle_packet(Wireguard(pkt_bytes))

        if first_result is None or not first_result.haslayer(Raw):
            return self._fail(target, f"Did not receive a valid echo reply after the valid handshake: {first_result!r}")

        return self._pass(target, "Target correctly dropped response with invalid mac1 and completed a valid handshake")
