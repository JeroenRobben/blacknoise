"""
Test: verify that the target correctly handles a cookie reply when acting as responder.

We act as the initiator. After receiving the target's handshake response we send
back a WireguardCookieReply instead of completing the handshake. The target must:
  1. Stay silent for ~10 seconds (not resend the response).
  2. When we send a new handshake initiation, reply with a response that has mac2
     set to a value derived from the cookie we sent.
"""
import socket

from scapy.contrib.wireguard import Wireguard, WireguardResponse

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget
from black_noise.state_machine import calc_mac_2, create_cookie_reply, WgStateActiveInitiator

SILENCE_WINDOW = 10.0


class TestCookieInitiator(AbstractTestCase):
    """
    We act as the initiator. We send a cookie reply in response to the target's
    handshake response, verify the target stays silent, then send a new initiation
    and verify the response carries a valid mac2.
    """

    @property
    def name(self) -> str:
        return "cookie_initiator"

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target)
        session = self._new_session(target)

        # Step 1: Send handshake initiation.
        init_pkt = session.init_handshake(peer_public_key=target.target_public_key)
        sock.sendto(bytes(init_pkt), (target.target_physical_ip, target.target_wg_port))

        # Step 2: Receive handshake response.
        try:
            pkt_bytes, target_addr = sock.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, "Did not receive handshake response")

        response = Wireguard(pkt_bytes)
        if not isinstance(response.payload, WireguardResponse):
            return self._fail(target, f"Expected handshake response, got {response.payload.__class__.__name__}")

        response_pkt = response.payload

        # Step 3: Send a cookie reply back to the target.
        cookie_reply_pkt, our_cookie = create_cookie_reply(response_pkt, session.server_public_key)
        sock.sendto(bytes(cookie_reply_pkt), target_addr)

        # Step 4: Wait — target must not send anything during the silence window.
        sock.settimeout(SILENCE_WINDOW)
        try:
            pkt_bytes, _ = sock.recvfrom(65535)
            pkt = Wireguard(pkt_bytes)
            if isinstance(pkt.payload, WireguardResponse):
                return self._fail(target, "Target resent the handshake response after receiving cookie reply — should stay silent")
            return self._fail(target, f"Target sent unexpected packet during silence window: {pkt.payload.__class__.__name__}")
        except socket.timeout:
            pass  # expected

        # Step 5: Send a new handshake initiation.
        session2 = self._new_session(target)
        init_pkt2 = session2.init_handshake(peer_public_key=target.target_public_key)
        sock.settimeout(5.0)
        sock.sendto(bytes(init_pkt2), (target.target_physical_ip, target.target_wg_port))

        # Step 6: Receive the new response — it must carry a valid mac2.
        try:
            pkt_bytes, target_addr = sock.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, "Did not receive response to second initiation")

        response2 = Wireguard(pkt_bytes)
        if not isinstance(response2.payload, WireguardResponse):
            return self._fail(target, f"Expected handshake response to second initiation, got {response2.payload.__class__.__name__}")

        response2_pkt = response2.payload

        if response2_pkt.mac2 == bytes(16):
            return self._fail(target, "Response to second initiation has mac2=0 — target did not use the cookie")

        expected_mac2 = calc_mac_2(response2_pkt, our_cookie)
        if response2_pkt.mac2 != expected_mac2:
            return self._fail(target, f"Response mac2 is invalid (got {response2_pkt.mac2.hex()}, expected {expected_mac2.hex()})")

        # Complete the handshake.
        pkt_keepalive = session2.handle_packet(response2)
        if not isinstance(session2.session_state, WgStateActiveInitiator):
            return self._fail(target, "Handshake did not complete after cookie exchange")

        sock.sendto(bytes(pkt_keepalive), target_addr)
        return self._pass(target, "Target stayed silent after cookie reply and sent response with valid mac2")
