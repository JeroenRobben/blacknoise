"""
Test: verify that the target supports roaming for the handshake response.

We act as the responder. The target sends its handshake initiation to our first
physical IP (server_physical_ip_1). We send the handshake response back from our
SECOND physical IP (server_physical_ip_2), simulating an endpoint change mid-handshake.

A roaming-capable target must:
  1. Accept the handshake response even though it arrives from a different IP.
  2. Update its endpoint and send the subsequent keepalive / echo reply to
     server_physical_ip_2 (i.e., the packet arrives on sock2, not sock1).
"""
import socket

from scapy.contrib.wireguard import Wireguard

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget
from scapy.packet import Raw


class TestRoamingResponder(AbstractTestCase):
    """
    We act as the responder. We receive the initiation on sock1, send the
    response from sock2, then verify the target's subsequent packet arrives
    on sock2 (confirming it updated its endpoint).
    """

    @property
    def name(self) -> str:
        return "roaming_responder"

    def run_test(self, target: TestTarget) -> TestReport:
        sock1, sock2 = self._open_sockets(target)
        session = self._new_session(target)

        self._probe(target)

        # Receive the handshake initiation on sock1 (target is configured with server_physical_ip_1).
        try:
            pkt_bytes, target_addr = sock1.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, "Did not receive handshake initiation on server_physical_ip_1")

        response = session.handle_packet(Wireguard(pkt_bytes))
        if response is None:
            return self._fail(target, "Failed to process handshake initiation")

        # Send the response from sock2 (server_physical_ip_2) — this is the roam.
        sock2.sendto(bytes(response), target_addr)

        # Expect the keepalive / echo reply to arrive on sock2.
        # If it arrives on sock1 instead, the target did not update its endpoint.
        try:
            pkt_bytes, _ = sock2.recvfrom(65535)
        except socket.timeout:
            # Nothing on sock2 — check if the target mistakenly replied to sock1.
            sock1.settimeout(0.5)
            try:
                sock1.recvfrom(65535)
                return self._fail(target, "Target sent post-handshake packet to server_physical_ip_1 instead of server_physical_ip_2 — roaming not supported")
            except socket.timeout:
                return self._fail(target, "Did not receive any packet after sending response from server_physical_ip_2")

        first_result = session.handle_packet(Wireguard(pkt_bytes))

        if first_result is None:
            # Keepalive — wait for the echo reply, also on sock2.
            try:
                pkt_bytes, _ = sock2.recvfrom(65535)
            except socket.timeout:
                return self._fail(target, "Received keepalive on sock2 but no echo reply followed")
            first_result = session.handle_packet(Wireguard(pkt_bytes))

        if first_result is None or not first_result.haslayer(Raw):
            return self._fail(target, f"Did not receive valid echo reply after roamed handshake: {first_result!r}")

        payload = bytes(first_result[Raw].load)
        if payload != self.name.encode():
            return self._fail(target, f"Echo reply payload mismatch: expected {self.name!r}, got {payload!r}")

        return self._pass(target, f"Roaming supported: target updated endpoint to {target.server_physical_ip_2} after receiving response from it")
