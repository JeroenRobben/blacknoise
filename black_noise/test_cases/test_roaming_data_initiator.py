"""
Test: verify that the target supports roaming when receiving a data packet
from the initiator.

We act as the initiator. We establish the handshake normally over sock1
(server_physical_ip_1). Once the session is active we send a transport packet
to the target's echo service from sock2 (server_physical_ip_2), simulating an
endpoint change mid-session.

A roaming-capable target must:
  1. Decrypt and process the transport packet even though it arrived from a new IP.
  2. Update its endpoint and send the echo reply back to server_physical_ip_2,
     i.e., the reply arrives on sock2, not sock1.
"""
import socket

from scapy.contrib.wireguard import Wireguard
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget
from black_noise.state_machine import WgStateActiveInitiator

ROAM_PAYLOAD = b"roam"


class TestRoamingDataInitiator(AbstractTestCase):
    """
    We act as the initiator. After establishing the session over sock1 we send
    a data packet from sock2 to trigger roaming and verify the echo reply arrives
    on sock2.
    """

    @property
    def name(self) -> str:
        return "roaming_data_initiator"

    def run_test(self, target: TestTarget) -> TestReport:
        sock1, sock2 = self._open_sockets(target)
        session = self._new_session(target)

        # Establish the session over sock1 (normal initiator path).
        init_pkt = session.init_handshake(peer_public_key=target.target_public_key)
        sock1.sendto(bytes(init_pkt), (target.target_physical_ip, target.target_wg_port))

        try:
            pkt_bytes, addr = sock1.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, "Did not receive handshake response on sock1")

        pkt_keepalive = session.handle_packet(Wireguard(pkt_bytes))
        if not isinstance(session.session_state, WgStateActiveInitiator):
            return self._fail(target, "Invalid handshake response")

        sock1.sendto(bytes(pkt_keepalive), (target.target_physical_ip, target.target_wg_port))

        # Session is now active. Send a data packet from sock2 to trigger roaming.
        # Use a distinct payload so it cannot be confused with other traffic.
        pkt_echo = (IP(src=target.server_wg_ip, dst=target.target_wg_ip)
                    / UDP(sport=target.echo_port, dport=target.echo_port)
                    / Raw(load=ROAM_PAYLOAD))
        sock2.sendto(bytes(session.encapsulate_transport_data(bytes(pkt_echo))),
                     (target.target_physical_ip, target.target_wg_port))

        # The echo reply must arrive on sock2 (target updated its endpoint).
        try:
            pkt_bytes, _ = sock2.recvfrom(65535)
        except socket.timeout:
            sock1.settimeout(0.5)
            try:
                sock1.recvfrom(65535)
                return self._fail(target, "Target sent echo reply to server_physical_ip_1 instead of server_physical_ip_2 — roaming not supported")
            except socket.timeout:
                return self._fail(target, "Did not receive echo reply on server_physical_ip_2 after sending data packet from it")

        echo_reply = session.handle_packet(Wireguard(pkt_bytes))

        if echo_reply is None or not echo_reply.haslayer(Raw):
            return self._fail(target, f"Did not receive valid echo reply after roaming data packet: {echo_reply!r}")

        payload = bytes(echo_reply[Raw].load)
        if payload != ROAM_PAYLOAD:
            return self._fail(target, f"Echo reply payload mismatch: expected {ROAM_PAYLOAD!r}, got {payload!r}")

        return self._pass(target, f"Roaming supported: target updated endpoint to {target.server_physical_ip_2} after receiving data packet from it")
