"""
Test: target must reject a replayed handshake response when already in the
ActiveInitiator state.

We act as responder: the target initiates the handshake, we respond, and a
session is established. We record the highest transport counter seen from the
target, then replay our original handshake response.

After the replay we probe the target's echo service. A correct implementation
ignores the replay and replies with a counter that continues past what we have
seen. A buggy implementation reinitialises the session, resetting its counter
to 0; the echo reply counter will then be ≤ the highest counter we observed
before the replay.
"""
import socket

from scapy.contrib.wireguard import Wireguard, WireguardTransport

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget
from black_noise.state_machine import WgStateActiveResponder


class TestHandshakeResponseReplay(AbstractTestCase):

    @property
    def name(self) -> str:
        return "handshake_response_replay"

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target)
        session = self._new_session(target)

        self._probe(target)

        try:
            pkt_bytes, addr = sock.recvfrom(65535)
        except socket.timeout:
            return self._error(target, "Did not receive handshake initiation")

        init_pkt = Wireguard(pkt_bytes)
        if init_pkt.message_type != 1:
            return self._error(target, f"Expected hs_initiation (type 1), got type {init_pkt.message_type}")

        # Process the initiation and send the response; save it for replay later.
        hs_response = session.handle_packet(init_pkt)
        sock.sendto(bytes(hs_response), addr)

        # Receive transport packets and track the highest counter seen.
        highest_counter = -1
        try:
            pkt_bytes, _ = sock.recvfrom(65535)
        except socket.timeout:
            return self._error(target, "Did not receive transport data after handshake response")

        wg_pkt = Wireguard(pkt_bytes)
        if isinstance(wg_pkt.payload, WireguardTransport):
            highest_counter = wg_pkt[WireguardTransport].counter
        result = session.handle_packet(wg_pkt)
        if result is None:
            # Keepalive first — wait for the echo reply.
            try:
                pkt_bytes, _ = sock.recvfrom(65535)
            except socket.timeout:
                return self._error(target, "Received keepalive but no echo reply followed")
            wg_pkt = Wireguard(pkt_bytes)
            if isinstance(wg_pkt.payload, WireguardTransport):
                highest_counter = max(highest_counter, wg_pkt[WireguardTransport].counter)
            session.handle_packet(wg_pkt)

        if not isinstance(session.session_state, WgStateActiveResponder):
            return self._error(target, "Session did not reach ActiveResponder state")

        # Drain any stragglers before replaying.
        self._drain(sock)

        # Replay the handshake response, then probe to trigger a transport reply.
        # If the target reset its session the reply counter will be ≤ highest_counter.
        sock.sendto(bytes(hs_response), addr)
        self._probe(target)

        try:
            pkt_bytes, _ = sock.recvfrom(65535)
        except socket.timeout:
            return self._pass(target, "Target correctly ignored the replayed handshake response")

        wg_pkt = Wireguard(pkt_bytes)
        if not isinstance(wg_pkt.payload, WireguardTransport):
            return self._error(target, f"Expected transport packet after echo, got message type {wg_pkt.message_type}")

        reply_counter = wg_pkt[WireguardTransport].counter
        if reply_counter <= highest_counter:
            return self._fail(target,
                f"Counter reset detected after replayed handshake response: "
                f"reply counter {reply_counter} \u2264 highest seen {highest_counter}")

        return self._pass(target, "Target correctly ignored the replayed handshake response")
