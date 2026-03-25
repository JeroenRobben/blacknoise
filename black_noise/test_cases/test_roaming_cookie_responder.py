"""
Test: verify that the target supports roaming when receiving a cookie reply.

We act as the responder with cookie sending enabled. The target sends its
handshake initiation to server_physical_ip_1 (sock1). We send the cookie reply
from server_physical_ip_2 (sock2), simulating an endpoint change.

A roaming-capable target must:
  1. Accept the cookie reply even though it arrives from a different IP.
  2. Update its endpoint and retransmit the initiation (with mac2 set) to
     server_physical_ip_2, i.e., the retransmit arrives on sock2.
We then complete the handshake from sock2 and verify the echo reply payload.
"""
import socket

from scapy.contrib.wireguard import Wireguard, WireguardCookieReply, WireguardInitiation
from scapy.packet import Raw

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget

RECV_TIMEOUT = 20.0  # must accommodate REKEY_TIMEOUT before the retransmit arrives


class TestRoamingCookieResponder(AbstractTestCase):
    """
    We act as the responder with send_cookie=True. We receive the initiation on
    sock1 and send the cookie reply from sock2. We then verify the retransmitted
    initiation arrives on sock2 (target updated its endpoint), complete the
    handshake, and verify the echo reply payload.
    """

    @property
    def name(self) -> str:
        return "roaming_cookie_responder"

    def run_test(self, target: TestTarget) -> TestReport:
        sock1, sock2 = self._open_sockets(target, timeout=RECV_TIMEOUT)
        session = self._new_session(target)
        session.send_cookie = True

        self._probe(target)

        # Receive the handshake initiation on sock1.
        try:
            pkt_bytes, target_addr = sock1.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, "Did not receive handshake initiation on server_physical_ip_1")

        cookie_reply = session.handle_packet(Wireguard(pkt_bytes))
        if cookie_reply is None or not isinstance(cookie_reply.payload, WireguardCookieReply):
            return self._fail(target, "Expected to send a cookie reply but state machine returned something else")

        # Send the cookie reply from sock2 — this is the roam.
        sock2.sendto(bytes(cookie_reply), target_addr)

        # Expect the retransmitted initiation to arrive on sock2.
        # If it arrives on sock1 instead, the target did not update its endpoint.
        try:
            pkt_bytes, target_addr = sock2.recvfrom(65535)
        except socket.timeout:
            sock1.settimeout(0.5)
            try:
                sock1.recvfrom(65535)
                return self._fail(target, "Target retransmitted initiation to server_physical_ip_1 instead of server_physical_ip_2 — roaming with cookie reply not supported")
            except socket.timeout:
                return self._fail(target, f"Target did not retransmit initiation within {RECV_TIMEOUT}s after receiving cookie reply")

        retransmit = Wireguard(pkt_bytes)
        if not isinstance(retransmit.payload, WireguardInitiation):
            return self._fail(target, f"Expected retransmitted initiation, got {retransmit.payload.__class__.__name__}")

        if retransmit.payload.mac2 == bytes(16):
            return self._fail(target, "Retransmitted initiation has mac2=0 — target did not use the cookie")

        # Process the retransmit and send the handshake response from sock2.
        try:
            handshake_response = session.handle_packet(retransmit)
        except ValueError as e:
            return self._fail(target, f"mac2 validation failed on retransmitted initiation: {e}")

        if handshake_response is None:
            return self._fail(target, "Failed to process retransmitted initiation")

        sock2.sendto(bytes(handshake_response), target_addr)

        # Expect the keepalive / echo reply on sock2.
        sock2.settimeout(5.0)
        try:
            pkt_bytes, _ = sock2.recvfrom(65535)
        except socket.timeout:
            sock1.settimeout(0.5)
            try:
                sock1.recvfrom(65535)
                return self._fail(target, "Target sent post-handshake packet to server_physical_ip_1 instead of server_physical_ip_2 — roaming not supported")
            except socket.timeout:
                return self._fail(target, "Did not receive any packet after handshake response")

        first_result = session.handle_packet(Wireguard(pkt_bytes))

        if first_result is None:
            # Keepalive — wait for the echo reply on sock2.
            try:
                pkt_bytes, _ = sock2.recvfrom(65535)
            except socket.timeout:
                return self._fail(target, "Received keepalive on sock2 but no echo reply followed")
            first_result = session.handle_packet(Wireguard(pkt_bytes))

        if first_result is None or not first_result.haslayer(Raw):
            return self._fail(target, f"Did not receive valid echo reply after roamed cookie handshake: {first_result!r}")

        payload = bytes(first_result[Raw].load)
        if payload != self.name.encode():
            return self._fail(target, f"Echo reply payload mismatch: expected {self.name!r}, got {payload!r}")

        return self._pass(target, f"Roaming supported: target updated endpoint to {target.server_physical_ip_2} after receiving cookie reply from it")
