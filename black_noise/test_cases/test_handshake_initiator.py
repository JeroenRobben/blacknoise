"""
Test: verify that the target completes a WireGuard handshake when we initiate one.
"""
from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget


class TestHandshakeInitiation(AbstractTestCase):
    """
    We act as the initiator. The target should respond and complete the
    WireGuard handshake, leaving us in an active session state. Then we check whether we can send / receive data packets.
    """

    @property
    def name(self) -> str:
        return "handshake_initiation"

    def run_test(self, target: TestTarget) -> TestReport:
        self._open_sockets(target)
        if report := self._verify_as_initiator(target):
            return report
        return self._pass(target, "Handshake completed and transport session established")
