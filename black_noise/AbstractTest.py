import socket
from abc import abstractmethod, ABC

from scapy.contrib.wireguard import Wireguard
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from black_noise.TestResult import TestReport, TestStatus
from black_noise.TestTarget import TestTarget
from black_noise.state_machine import WgSecureSession, WgStateActiveInitiator


class AbstractTestCase(ABC):
    _socks: list[socket.socket] = []

    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError()

    @abstractmethod
    def run_test(self, target: TestTarget) -> TestReport:
        raise NotImplementedError()

    def _open_sockets(self, target: TestTarget, timeout: float = 3.0) -> tuple[socket.socket, socket.socket]:
        """Create two UDP sockets bound to server_physical_ip_1 and server_physical_ip_2."""
        self._socks = []
        for ip in (target.server_physical_ip_1, target.server_physical_ip_2):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind((ip, target.server_wg_port))
            sock.settimeout(timeout)
            self._socks.append(sock)
        return self._socks[0], self._socks[1]

    def _new_session(self, target: TestTarget) -> WgSecureSession:
        """Create a WgSecureSession for the given target (cookie sending disabled)."""
        session = WgSecureSession(server_private_key=target.server_private_key,
                                  preshared_symmetric_key=target.preshared_key or bytes(32))
        session.send_cookie = False
        return session

    def _probe(self, target: TestTarget):
        """Send a UDP probe to the target's echo service to trigger a handshake initiation."""
        probe_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        probe_sock.sendto(self.name.encode(), (target.target_physical_ip, target.echo_port))
        probe_sock.close()

    def _drain(self, sock: socket.socket) -> None:
        """Discard all packets currently queued on sock (non-blocking)."""
        old_timeout = sock.gettimeout()
        sock.setblocking(False)
        try:
            while True:
                sock.recvfrom(65535)
        except BlockingIOError:
            pass
        finally:
            sock.setblocking(True)
            sock.settimeout(old_timeout)

    def _verify_as_initiator(self, target: TestTarget) -> TestReport | None:
        """Perform a fresh handshake as initiator and verify a UDP echo through the tunnel.

        Drains the first socket before starting. Returns None on success, or a
        TestReport on failure/error so the caller can do:
            if report := self._verify_as_initiator(...): return report
        """
        sock = self._socks[0]
        self._drain(sock)
        session = self._new_session(target)
        init_pkt = session.init_handshake(peer_public_key=target.target_public_key)
        sock.sendto(bytes(init_pkt), (target.target_physical_ip, target.target_wg_port))
        try:
            pkt_bytes, _ = sock.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, "Target did not respond to the valid initiation")

        pkt_keepalive = session.handle_packet(Wireguard(pkt_bytes))
        if not isinstance(session.session_state, WgStateActiveInitiator):
            return self._fail(target, "Valid initiation was not completed into an active session")

        sock.sendto(bytes(pkt_keepalive), (target.target_physical_ip, target.target_wg_port))

        pkt_echo = (IP(src=target.server_wg_ip, dst=target.target_wg_ip)
                    / UDP(sport=target.echo_port, dport=target.echo_port)
                    / Raw(load=self.name.encode()))
        sock.sendto(bytes(session.encapsulate_transport_data(bytes(pkt_echo))),
                    (target.target_physical_ip, target.target_wg_port))

        try:
            pkt_bytes, _ = sock.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, "Target did not send an echo reply through the tunnel")

        echo_reply = session.handle_packet(Wireguard(pkt_bytes))
        if echo_reply is None or not echo_reply.haslayer(Raw) or bytes(echo_reply[Raw].load) != self.name.encode():
            return self._fail(target, f"Echo reply payload mismatch: {echo_reply!r}")

        return None

    def _verify_as_responder(self, target: TestTarget) -> TestReport | None:
        """Probe the target, complete the handshake as responder, then verify the echo reply.

        Drains the first socket before starting. Returns None on success, or a
        TestReport on failure/error so the caller can do:
            if report := self._verify_as_responder(...): return report
        """
        sock = self._socks[0]
        self._drain(sock)
        self._probe(target)
        try:
            pkt_bytes, addr = sock.recvfrom(65535)
        except socket.timeout:
            return self._error(target, "Target did not send a handshake initiation")

        init_pkt = Wireguard(pkt_bytes)
        if init_pkt.message_type != 1:
            return self._fail(target,
                f"Expected handshake initiation (type 1), got type {init_pkt.message_type}")

        session = self._new_session(target)
        sock.sendto(bytes(session.handle_packet(init_pkt)), addr)

        try:
            pkt_bytes, _ = sock.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, "Target did not send transport data after a valid handshake response")

        result = session.handle_packet(Wireguard(pkt_bytes))
        if result is None:
            # Keepalive received first — wait for the queued echo reply.
            try:
                pkt_bytes, _ = sock.recvfrom(65535)
            except socket.timeout:
                return self._fail(target, "Received keepalive but no echo reply followed")
            result = session.handle_packet(Wireguard(pkt_bytes))

        if result is None or not result.haslayer(Raw) or bytes(result[Raw].load) != self.name.encode():
            return self._fail(target, f"Echo reply payload mismatch: {result!r}")

        return None

    def _expect_reply(self, sock: socket.socket, session, target: TestTarget,
                      expected: bytes, label: str) -> TestReport | None:
        """Receive one transport packet and verify its decrypted payload matches expected.

        Returns None on success, or a fail TestReport so the caller can do:
            if report := self._expect_reply(...): return report
        """
        try:
            pkt_bytes, _ = sock.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, f"{label}: expected echo reply but got none")
        result = session.handle_packet(Wireguard(pkt_bytes))
        if result is None or not result.haslayer(Raw) or bytes(result[Raw].load) != expected:
            return self._fail(target, f"{label}: payload mismatch (got {result!r})")
        return None

    def _expect_silence(self, sock: socket.socket, target: TestTarget, label: str) -> TestReport | None:
        """Assert that no packet arrives within the socket timeout.

        Returns None if silent (expected), or a fail TestReport if a packet arrives.
        """
        try:
            sock.recvfrom(65535)
            return self._fail(target, f"{label}: expected silence but got a reply")
        except socket.timeout:
            return None

    def _pass(self, target: TestTarget, message: str = "") -> TestReport:
        for sock in self._socks:
            sock.close()
        return TestReport(TestStatus.PASS, target.name, self.name, message)

    def _error(self, target: TestTarget, message: str) -> TestReport:
        for sock in self._socks:
            sock.close()
        return TestReport(TestStatus.ERROR, target.name, self.name, message)

    def _fail(self, target: TestTarget, message: str) -> TestReport:
        for sock in self._socks:
            sock.close()
        return TestReport(TestStatus.FAIL, target.name, self.name, message)
