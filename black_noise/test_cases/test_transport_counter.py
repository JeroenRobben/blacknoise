"""
Test: verify that the target correctly implements the transport message counter
and sliding window replay protection.

We act as the initiator. After completing the handshake (which sends a
keepalive on counter 0) we craft transport packets with explicit counter values
using the session's sending key directly. We then verify:

  1. Normal counter (1) is accepted.
  2. Replay of counter 1 is rejected.
  3. Out-of-order counter within the window (3 before 2) is accepted.
  4. Filling the gap (counter 2) is accepted.
  5. Replay of the out-of-order counter (2) is rejected.
  6. A large counter (WINDOW_SIZE + 10) that pushes old counters outside the
     window is accepted.
  7. Counter 4 — unseen, but below the window lower bound — is rejected.
  8. The next sequential counter is accepted, confirming the target still works.

"""
import socket

from scapy.contrib.wireguard import Wireguard, WireguardTransport
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget
from black_noise.primitives import wg_aead_encrypt
from black_noise.state_machine import WgStateActiveInitiator

WINDOW_SIZE    = 8192


class TestTransportCounter(AbstractTestCase):
    """
    We act as the initiator. We craft transport packets with explicit counter
    values to verify replay detection and sliding window behaviour.
    """

    @property
    def name(self) -> str:
        return "transport_counter"

    def _make_transport(self, session, counter: int, target: TestTarget, payload: bytes) -> bytes:
        """Encrypt an echo packet with the given counter and payload."""
        inner = bytes(
            IP(src=target.server_wg_ip, dst=target.target_wg_ip)
            / UDP(sport=target.echo_port, dport=target.echo_port)
            / Raw(load=payload)
        )
        state = session.session_state
        pkt = WireguardTransport()
        pkt.receiver_index = state.session.peer_session_index
        pkt.counter = counter
        pkt.encrypted_encapsulated_packet = wg_aead_encrypt(
            key=state.t_send_i, counter=counter, plain_text=inner, auth_text=b'')
        return bytes(Wireguard() / pkt)

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target)

        # Establish session as initiator. The handshake sends a keepalive on
        # counter 0; ctr_send is initialised to 1.
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

        addr = (target.target_physical_ip, target.target_wg_port)

        # 1. Counter 1 — accepted.
        sock.sendto(self._make_transport(session, 1, target, b"step1"), addr)
        if report := self._expect_reply(sock, session, target, b"step1", "counter 1 (first valid)"):
            return report

        # 2. Replay counter 1 — rejected.
        sock.sendto(self._make_transport(session, 1, target, b"step2"), addr)
        if report := self._expect_silence(sock, target, "counter 1 replay"):
            return report

        # 3. Counter 3 (out of order, skipping 2) — accepted.
        sock.sendto(self._make_transport(session, 3, target, b"step3"), addr)
        if report := self._expect_reply(sock, session, target, b"step3", "counter 3 (out of order)"):
            return report

        # 4. Counter 2 (filling the gap) — accepted.
        sock.sendto(self._make_transport(session, 2, target, b"step4"), addr)
        if report := self._expect_reply(sock, session, target, b"step4", "counter 2 (fill gap)"):
            return report

        # 5. Replay counter 2 — rejected.
        sock.sendto(self._make_transport(session, 2, target, b"step5"), addr)
        if report := self._expect_silence(sock, target, "counter 2 replay"):
            return report

        # 6. High counter (WINDOW_SIZE + 10) — accepted; advances window so
        #    that counter 4 falls outside it.
        high = WINDOW_SIZE + 10
        sock.sendto(self._make_transport(session, high, target, b"step6"), addr)
        if report := self._expect_reply(sock, session, target, b"step6", f"counter {high} (advance window)"):
            return report

        # 7. Counter 4 — unseen, but below the window lower bound (high - WINDOW_SIZE + 1 = 11),
        #    so it must be rejected as outside the window.
        sock.sendto(self._make_transport(session, 4, target, b"step7"), addr)
        if report := self._expect_silence(sock, target, "counter 4 (outside window, never seen before)"):
            return report

        # 8. Counter high + 1 — accepted, confirming the target still works.
        sock.sendto(self._make_transport(session, high + 1, target, b"step8"), addr)
        if report := self._expect_reply(sock, session, target, b"step8", f"counter {high + 1} (valid after window advance)"):
            return report

        return self._pass(target, "Transport counter and sliding window replay protection verified")
