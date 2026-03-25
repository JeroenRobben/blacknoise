"""
Test: verify that the target supports roaming for the handshake initiation.

We act as the initiator and send the handshake initiation from sock2
(server_physical_ip_2) rather than the address the target may have configured
for us (server_physical_ip_1). The target must:
  1. Accept the initiation and send the handshake response back to sock2.
  2. Continue sending data packets to sock2 throughout the session.
"""
import socket

from scapy.contrib.wireguard import Wireguard
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget
from black_noise.state_machine import WgStateActiveInitiator


class TestRoamingInitiator(AbstractTestCase):
    """
    We act as the initiator sending from sock2. We verify the response and all
    subsequent data arrive on sock2, not sock1.
    """

    @property
    def name(self) -> str:
        return "roaming_initiator"

    def run_test(self, target: TestTarget) -> TestReport:
        sock1, sock2 = self._open_sockets(target)
        session = self._new_session(target)

        # Send the handshake initiation from sock2 (the roam).
        init_pkt = session.init_handshake(peer_public_key=target.target_public_key)
        sock2.sendto(bytes(init_pkt), (target.target_physical_ip, target.target_wg_port))

        # Expect the handshake response on sock2.
        try:
            pkt_bytes, addr = sock2.recvfrom(65535)
        except socket.timeout:
            sock1.settimeout(0.5)
            try:
                sock1.recvfrom(65535)
                return self._fail(target, "Target sent handshake response to server_physical_ip_1 instead of server_physical_ip_2 — roaming not supported")
            except socket.timeout:
                return self._fail(target, "Did not receive handshake response")

        pkt_keepalive = session.handle_packet(Wireguard(pkt_bytes))
        if not isinstance(session.session_state, WgStateActiveInitiator):
            return self._fail(target, "Invalid handshake response")

        sock2.sendto(bytes(pkt_keepalive), (target.target_physical_ip, target.target_wg_port))

        # Send a data packet through the tunnel from sock2 and verify the echo reply.
        pkt_echo = (IP(src=target.server_wg_ip, dst=target.target_wg_ip)
                    / UDP(sport=target.echo_port, dport=target.echo_port)
                    / Raw(load=self.name.encode()))
        sock2.sendto(bytes(session.encapsulate_transport_data(bytes(pkt_echo))),
                     (target.target_physical_ip, target.target_wg_port))

        try:
            pkt_bytes, _ = sock2.recvfrom(65535)
        except socket.timeout:
            sock1.settimeout(0.5)
            try:
                sock1.recvfrom(65535)
                return self._fail(target, "Target sent echo reply to server_physical_ip_1 instead of server_physical_ip_2 — roaming not supported")
            except socket.timeout:
                return self._fail(target, "Did not receive echo reply on server_physical_ip_2")

        echo_reply = session.handle_packet(Wireguard(pkt_bytes))

        if echo_reply is None or not echo_reply.haslayer(Raw):
            return self._fail(target, f"Did not receive valid echo reply: {echo_reply!r}")

        payload = bytes(echo_reply[Raw].load)
        if payload != self.name.encode():
            return self._fail(target, f"Echo reply payload mismatch: expected {self.name!r}, got {payload!r}")

        return self._pass(target, f"Roaming supported: target responded to initiation from {target.server_physical_ip_2}")
