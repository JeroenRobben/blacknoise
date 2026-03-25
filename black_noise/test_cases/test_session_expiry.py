"""
Test: verify that the target rejects transport packets on a session that has
exceeded REJECT-AFTER-TIME (180 seconds).

We act as the initiator. The target is the responder and must not send
handshake initiations — opportunistic re-keying is the initiator's
responsibility. If the target sends a handshake initiation at any point the
test fails immediately.

After completing the handshake we continuously send UDP echo requests through
the tunnel once per second until echo requests time out. We then verify that
the session was rejected within the expected window around REJECT-AFTER-TIME.

Timeline:
  0 s     — session established
  ~180 s  — target stops accepting transport packets (REJECT-AFTER-TIME);
             our echo requests time out
"""
import socket
import time

from scapy.contrib.wireguard import Wireguard
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget
from black_noise.state_machine import WgStateActiveInitiator

REJECT_AFTER_TIME = 180  # seconds, per WireGuard spec
ECHO_INTERVAL     = 1.0  # seconds between echo requests
REPLY_TIMEOUT     = 3.0  # seconds to wait for each echo reply
TOLERANCE         = 30   # seconds of allowed deviation around REJECT-AFTER-TIME
MAX_DURATION      = REJECT_AFTER_TIME + TOLERANCE + 10


class TestSessionExpiry(AbstractTestCase):
    """
    We act as the initiator. We keep sending echo requests and fail immediately
    if the target (responder) sends a handshake initiation. We then verify the
    session is rejected within the expected window around REJECT-AFTER-TIME.
    """

    @property
    def name(self) -> str:
        return "session_expiry"

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target)

        # Establish session as initiator.
        session = self._new_session(target)
        init_pkt = session.init_handshake(peer_public_key=target.target_public_key)
        sock.sendto(bytes(init_pkt), (target.target_physical_ip, target.target_wg_port))

        try:
            pkt_bytes, _ = sock.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, "Target did not respond to handshake initiation")

        pkt_keepalive = session.handle_packet(Wireguard(pkt_bytes))
        if not isinstance(session.session_state, WgStateActiveInitiator):
            return self._fail(target, "Handshake did not complete into an active session")

        sock.sendto(bytes(pkt_keepalive), (target.target_physical_ip, target.target_wg_port))

        session_start = time.monotonic()

        while True:
            elapsed = time.monotonic() - session_start
            if elapsed > MAX_DURATION:
                return self._fail(target,
                    f"Session was not rejected within {MAX_DURATION:.0f}s "
                    f"(expected rejection at ~{REJECT_AFTER_TIME}s)")

            pkt_echo = (IP(src=target.server_wg_ip, dst=target.target_wg_ip)
                        / UDP(sport=target.echo_port, dport=target.echo_port)
                        / Raw(load=b"A"))
            sock.sendto(bytes(session.encapsulate_transport_data(bytes(pkt_echo))),
                        (target.target_physical_ip, target.target_wg_port))

            # Wait for a transport reply; fail immediately on any handshake initiation.
            deadline = time.monotonic() + REPLY_TIMEOUT
            got_reply = False
            while time.monotonic() < deadline:
                sock.settimeout(max(deadline - time.monotonic(), 0.01))
                try:
                    pkt_bytes, _ = sock.recvfrom(65535)
                    wg_pkt = Wireguard(pkt_bytes)
                    if wg_pkt.message_type == 1:
                        return self._fail(target,
                            f"Target sent a handshake initiation at {time.monotonic() - session_start:.1f}s "
                            f"— the responder must not perform opportunistic re-keying")
                    session.handle_packet(wg_pkt)
                    got_reply = True
                    break
                except socket.timeout:
                    break

            if not got_reply:
                elapsed = time.monotonic() - session_start
                if elapsed < REJECT_AFTER_TIME - TOLERANCE:
                    return self._fail(target,
                        f"Session rejected too early at {elapsed:.1f}s "
                        f"(expected ~{REJECT_AFTER_TIME}s)")
                return self._pass(target,
                    f"Session correctly rejected after {elapsed:.1f}s "
                    f"(REJECT-AFTER-TIME = {REJECT_AFTER_TIME}s)")

            time.sleep(ECHO_INTERVAL)
