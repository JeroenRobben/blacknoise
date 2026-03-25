"""
Test: verify that the target can initiate a WireGuard handshake and that we
successfully complete it as the responder.

We trigger the target by sending a UDP packet directly to its echo service
(target_ip:echo_port). The echo script tries to reply to server_wg_ip:echo_port
via the WireGuard tunnel, which causes the target to initiate a handshake.
After the session is established the echo reply arrives as a transport packet.
"""
from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget


class TestHandshakeResponder(AbstractTestCase):
    """
    We act as the responder. We trigger the target's echo service to provoke a
    handshake initiation, complete the handshake, then verify the echo reply
    arrives correctly through the tunnel.
    """

    @property
    def name(self) -> str:
        return "handshake_responder"

    def run_test(self, target: TestTarget) -> TestReport:
        self._open_sockets(target)
        if report := self._verify_as_responder(target):
            return report
        return self._pass(target, "Handshake completed as responder")
