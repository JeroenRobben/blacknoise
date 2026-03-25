"""
Test: verify that the target supports roaming for the cookie reply message.

We act as the initiator. We send the handshake initiation from sock1 and receive
the handshake response on sock1. Instead of completing the handshake we send a
cookie reply from sock2 — the roam. The target must:
  1. Stay silent (not resend the response) during the silence window.
  2. When we send a new initiation from sock2, reply with a response carrying
     a valid mac2 and send it to sock2 (target updated its endpoint).
"""
import socket

from scapy.contrib.wireguard import Wireguard, WireguardResponse

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget
from black_noise.state_machine import calc_mac_2, create_cookie_reply, WgStateActiveInitiator

SILENCE_WINDOW = 10.0


class TestRoamingCookieInitiator(AbstractTestCase):
    """
    We act as the initiator. We send a cookie reply from sock2 in response to
    the target's handshake response (received on sock1), then verify the target
    stays silent, and that the subsequent handshake response arrives on sock2.
    """

    @property
    def name(self) -> str:
        return "roaming_cookie_initiator"

    def run_test(self, target: TestTarget) -> TestReport:
        sock1, sock2 = self._open_sockets(target)
        session = self._new_session(target)

        # Step 1: Send handshake initiation from sock1.
        init_pkt = session.init_handshake(peer_public_key=target.target_public_key)
        sock1.sendto(bytes(init_pkt), (target.target_physical_ip, target.target_wg_port))

        # Step 2: Receive handshake response on sock1.
        try:
            pkt_bytes, target_addr = sock1.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, "Did not receive handshake response on sock1")

        response = Wireguard(pkt_bytes)
        if not isinstance(response.payload, WireguardResponse):
            return self._fail(target, f"Expected handshake response, got {response.payload.__class__.__name__}")

        response_pkt = response.payload

        # Step 3: Send a cookie reply from sock2 instead of completing the handshake.
        cookie_reply_pkt, our_cookie = create_cookie_reply(response_pkt, session.server_public_key)
        sock2.sendto(bytes(cookie_reply_pkt), target_addr)

        # Step 4: Wait — target must not send anything on either socket.
        # Drain both sockets for the full silence window using a simple poll loop.
        import time
        deadline = time.monotonic() + SILENCE_WINDOW
        while time.monotonic() < deadline:
            for sock, label in ((sock1, "server_physical_ip_1"), (sock2, "server_physical_ip_2")):
                sock.settimeout(0.1)
                try:
                    pkt_bytes, _ = sock.recvfrom(65535)
                    pkt = Wireguard(pkt_bytes)
                    if isinstance(pkt.payload, WireguardResponse):
                        return self._fail(target, f"Target resent handshake response to {label} after receiving cookie reply — should stay silent")
                    return self._fail(target, f"Target sent unexpected packet to {label} during silence window: {pkt.payload.__class__.__name__}")
                except socket.timeout:
                    pass

        # Step 5: Send a new handshake initiation from sock2.
        session2 = self._new_session(target)
        init_pkt2 = session2.init_handshake(peer_public_key=target.target_public_key)
        sock2.sendto(bytes(init_pkt2), (target.target_physical_ip, target.target_wg_port))

        # Step 6: Receive the new response on sock2 — it must carry a valid mac2.
        try:
            sock2.settimeout(5.0)
            pkt_bytes, target_addr = sock2.recvfrom(65535)
        except socket.timeout:
            sock1.settimeout(0.5)
            try:
                sock1.recvfrom(65535)
                return self._fail(target, "Target sent response to server_physical_ip_1 instead of server_physical_ip_2 — roaming not supported")
            except socket.timeout:
                return self._fail(target, "Did not receive response to second initiation on sock2")

        response2 = Wireguard(pkt_bytes)
        if not isinstance(response2.payload, WireguardResponse):
            return self._fail(target, f"Expected handshake response, got {response2.payload.__class__.__name__}")

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

        sock2.sendto(bytes(pkt_keepalive), (target.target_physical_ip, target.target_wg_port))
        return self._pass(target, f"Roaming supported: target stayed silent after cookie reply from sock2, then responded with valid mac2 to sock2")
