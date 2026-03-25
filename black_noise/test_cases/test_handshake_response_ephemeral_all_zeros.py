"""
Test: verify that the target rejects a handshake response whose unencrypted_ephemeral
is the all-zeros point (0x00 * 32), the X25519 identity point.

A DH with this key always produces an all-zeros output. WireGuard implementations
must detect and reject it.

We act as the responder: we probe the target's echo service to trigger it to send
us a handshake initiation, then reply with a response built using a session
constructed with a fabricated ephemeral keypair whose public half is all-zeros.
handle_hs_initiation reads the ephemeral from the session, so the entire response
— including encrypted_nothing — is derived from the bad ephemeral. mac1 for a
response is keyed on the initiator's static public key.

A positive outcome is the target NOT sending transport data (type 4) after our
bad response. We then perform a clean valid handshake to confirm the target still
processes valid responses.
"""
import socket

from scapy.contrib.wireguard import Wireguard

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget
from black_noise.test_cases.bad_keys import ALL_ZEROS
from black_noise.primitives import wg_dh_generate
from black_noise.state_machine import WgSecureSession

SOCKET_TIMEOUT = 10.0


class TestHandshakeResponseEphemeralAllZeros(AbstractTestCase):
    """
    We act as the responder. We send a handshake response with an all-zeros
    unencrypted_ephemeral. The target must not send transport data in reply.
    A subsequent clean handshake must succeed.
    """

    @property
    def name(self) -> str:
        return "handshake_response_ephemeral_all_zeros"

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target, timeout=SOCKET_TIMEOUT)

        self._probe(target)

        try:
            pkt_bytes, addr = sock.recvfrom(65535)
        except socket.timeout:
            return self._error(target, "Target did not send a handshake initiation")

        init_pkt = Wireguard(pkt_bytes)
        if init_pkt.message_type != 1:
            return self._error(target,
                f"Expected handshake initiation (type 1), got type {init_pkt.message_type}")

        e_priv_fake, _ = wg_dh_generate()
        session = WgSecureSession(
            server_private_key=target.server_private_key,
            preshared_symmetric_key=target.preshared_key or bytes(32),
            ephemeral_keypair=(e_priv_fake, ALL_ZEROS),
        )
        session.send_cookie = False
        bad_resp = session.handle_packet(init_pkt)

        sock.sendto(bytes(bad_resp), addr)

        try:
            reply_bytes, _ = sock.recvfrom(65535)
            reply = Wireguard(reply_bytes)
            if reply.message_type == 4:
                return self._fail(target,
                    "Target sent transport data after a response with an all-zeros ephemeral key — "
                    "should have been silently dropped")
        except socket.timeout:
            pass  # expected

        # --- Valid handshake: confirm the target still works ---
        if report := self._verify_as_responder(target):
            return report
        return self._pass(target,
            "Target correctly dropped the response with an all-zeros ephemeral key and completed a valid handshake")
