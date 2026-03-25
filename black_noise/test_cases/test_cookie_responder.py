"""
Test: verify that the target correctly handles the cookie protocol when acting as initiator.

We act as the responder with cookie sending enabled. When the target sends its first
handshake initiation (mac2=0), we reply with a WireguardCookieReply instead of a
handshake response. The target must:
  1. Wait at least REKEY_TIMEOUT seconds before retransmitting (per the WireGuard spec).
  2. Retransmit the initiation with mac2 correctly set.
We then complete the handshake normally and verify the session is established.
"""
import socket
import time

from scapy.contrib.wireguard import Wireguard, WireguardCookieReply, WireguardInitiation
from scapy.packet import Raw

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget

REKEY_TIMEOUT = 5.0   # seconds — WireGuard spec value
RECV_TIMEOUT = 20.0   # long enough to catch the retransmit after REKEY_TIMEOUT


class TestCookieResponder(AbstractTestCase):
    """
    We act as the responder with send_cookie=True. We send a cookie reply to the
    target's first initiation, verify the retransmit arrives no sooner than
    REKEY_TIMEOUT seconds, check mac2 is set, then complete the handshake.
    """

    @property
    def name(self) -> str:
        return "cookie_responder"

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target, timeout=RECV_TIMEOUT)
        session = self._new_session(target)
        session.send_cookie = True

        self._probe(target)

        # Receive first initiation (mac2=0).
        try:
            pkt_bytes, target_addr = sock.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, "Did not receive handshake initiation")

        cookie_reply = session.handle_packet(Wireguard(pkt_bytes))

        sock.sendto(bytes(cookie_reply), target_addr)
        t_cookie_sent = time.monotonic()

        # Wait for the retransmitted initiation with mac2 set.
        try:
            pkt_bytes, target_addr = sock.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, f"Target did not retransmit initiation within {RECV_TIMEOUT}s after receiving cookie reply")

        elapsed = time.monotonic() - t_cookie_sent

        retransmit = Wireguard(pkt_bytes)
        if not isinstance(retransmit.payload, WireguardInitiation):
            return self._fail(target, f"Expected retransmitted initiation, got {retransmit.payload.__class__.__name__}")

        if elapsed < REKEY_TIMEOUT:
            return self._fail(target, f"Target retransmitted after only {elapsed:.2f}s — must wait at least {REKEY_TIMEOUT}s (REKEY_TIMEOUT)")

        if retransmit.payload.mac2 == bytes(16):
            return self._fail(target, "Retransmitted initiation has mac2=0 — target did not use the cookie")

        # Process the retransmit (state machine validates mac2 and returns handshake response).
        try:
            handshake_response = session.handle_packet(retransmit)
        except ValueError as e:
            return self._fail(target, f"mac2 validation failed on retransmitted initiation: {e}")

        if handshake_response is None:
            return self._fail(target, "Failed to process retransmitted initiation")

        sock.sendto(bytes(handshake_response), target_addr)

        # Wait for keepalive or echo reply to confirm the session is established.
        sock.settimeout(5.0)
        try:
            pkt_bytes, _ = sock.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, "Target did not send any packet after handshake response")

        first_result = session.handle_packet(Wireguard(pkt_bytes))

        if first_result is None:
            # Keepalive — wait for echo reply.
            try:
                pkt_bytes, _ = sock.recvfrom(65535)
            except socket.timeout:
                return self._fail(target, "Received keepalive but no echo reply followed")
            first_result = session.handle_packet(Wireguard(pkt_bytes))

        if first_result is None or not first_result.haslayer(Raw):
            return self._fail(target, f"Did not receive valid echo reply after cookie handshake: {first_result!r}")

        return self._pass(target, f"Cookie protocol completed: target retransmitted after {elapsed:.2f}s with mac2 set, session established")
