"""
Test: verify that the target enforces the cryptokey routing table check.

The target is configured to accept tunnel traffic only from server_wg_ip
(AllowedIPs = server_wg_ip/32). We send transport packets whose inner IP
header carries various spoofed source addresses and verify that only
server_wg_ip passes the check. Tested source IPs:

  1. server_wg_ip                 — accepted (baseline)
  2. target_wg_ip                 — dropped (target's own tunnel IP)
  3. server_wg_ip + 1             — dropped (adjacent address)
  4. same /24 subnet, .100        — dropped (in-subnet but not allowed)
  5. 10.20.30.40                  — dropped (completely different subnet)
  6. 127.0.0.1 src only           — dropped (loopback source, non-loopback dst)
  7. 127.0.0.1 src and dst        — dropped (loopback source and destination)
  8. server_wg_ip again           — accepted (target still functional)
"""
import ipaddress
import socket

from scapy.contrib.wireguard import Wireguard
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget
from black_noise.state_machine import WgStateActiveInitiator


class TestTransportCryptokeyRouting(AbstractTestCase):
    """
    We act as the initiator. After completing the handshake we send transport
    packets with various inner source IPs and verify that only server_wg_ip
    passes the target's cryptokey routing table check.
    """

    @property
    def name(self) -> str:
        return "cryptokey_routing"

    def _send_echo(self, sock: socket.socket, session, target: TestTarget, src_ip: str, payload: bytes) -> None:
        inner = bytes(
            IP(src=src_ip, dst=target.target_wg_ip)
            / UDP(sport=target.echo_port, dport=target.echo_port)
            / Raw(load=payload)
        )
        sock.sendto(bytes(session.encapsulate_transport_data(inner)),
                    (target.target_physical_ip, target.target_wg_port))

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target)

        # Establish session as initiator
        session = self._new_session(target)
        init_pkt = session.init_handshake(peer_public_key=target.target_public_key)
        sock.sendto(bytes(init_pkt), (target.target_physical_ip, target.target_wg_port))

        try:
            pkt_bytes, _ = sock.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, "Target did not respond to handshake initiation")

        keepalive = session.handle_packet(Wireguard(pkt_bytes))
        if not isinstance(session.session_state, WgStateActiveInitiator):
            return self._fail(target, "Handshake did not complete into an active session")
        sock.sendto(bytes(keepalive), (target.target_physical_ip, target.target_wg_port))

        server_ip = ipaddress.IPv4Address(target.server_wg_ip)

        # 1. Valid source IP — accepted
        self._send_echo(sock, session, target, str(server_ip), b"valid")
        if report := self._expect_reply(sock, session, target, b"valid",
                                        f"valid src {server_ip}"):
            return report

        # 2. Target's own tunnel IP — dropped
        self._send_echo(sock, session, target, target.target_wg_ip, b"target_ip")
        if report := self._expect_silence(sock, target,
                                          f"src = target_wg_ip ({target.target_wg_ip})"):
            return report

        # 3. server_wg_ip + 1 — adjacent address, dropped
        next_ip = server_ip + 1
        self._send_echo(sock, session, target, str(next_ip), b"next_ip")
        if report := self._expect_silence(sock, target,
                                          f"src = server_wg_ip + 1 ({next_ip})"):
            return report

        # 4. Same /24 subnet (.100), dropped
        subnet_100 = ipaddress.IPv4Address((int(server_ip) & 0xFFFFFF00) | 100)
        if subnet_100 == server_ip:
            subnet_100 = ipaddress.IPv4Address((int(server_ip) & 0xFFFFFF00) | 101)
        if subnet_100 == target.target_wg_ip:
            subnet_100 = ipaddress.IPv4Address((int(server_ip) & 0xFFFFFF00) | 102)
        self._send_echo(sock, session, target, str(subnet_100), b"subnet_ip")
        if report := self._expect_silence(sock, target,
                                          f"src = same /24 ({subnet_100})"):
            return report

        # 5. Completely different subnet — dropped
        self._send_echo(sock, session, target, "10.20.30.40", b"other_subnet")
        if report := self._expect_silence(sock, target,
                                          "src = 10.20.30.40 (different subnet)"):
            return report

        # 6. Loopback source, normal destination — dropped
        self._send_echo(sock, session, target, "127.0.0.1", b"loopback_src")
        if report := self._expect_silence(sock, target,
                                          "src = 127.0.0.1, dst = target_wg_ip"):
            return report

        # 7. Loopback source and destination — dropped
        inner = bytes(
            IP(src="127.0.0.1", dst="127.0.0.1")
            / UDP(sport=target.echo_port, dport=target.echo_port)
            / Raw(load=b"loopback_both")
        )
        sock.sendto(bytes(session.encapsulate_transport_data(inner)),
                    (target.target_physical_ip, target.target_wg_port))
        if report := self._expect_silence(sock, target,
                                          "src = 127.0.0.1, dst = 127.0.0.1"):
            return report

        # 8. Valid source IP again — confirm target still processes correct packets
        self._send_echo(sock, session, target, str(server_ip), b"final")
        if report := self._expect_reply(sock, session, target, b"final",
                                        "final valid packet"):
            return report

        return self._pass(target, "Target correctly enforces the cryptokey routing table")
