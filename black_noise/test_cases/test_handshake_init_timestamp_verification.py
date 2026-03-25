"""
Test: verify that the target checks and updates the timestamp in handshake
initiation messages.

WireGuard uses a TAI64N timestamp inside encrypted_timestamp to prevent replay
attacks. The responder must reject any initiation whose timestamp is not
strictly greater than the last accepted timestamp for that peer, and update
the stored timestamp when accepting a valid initiation.

We pre-create packets with 1-second gaps to ensure T1 < T2 < T3, plus a
separate packet (init2_dup) that carries the same T2 timestamp value but uses
a freshly generated ephemeral key pair and a different sender_index.

Test order:
  1. Send initiation 2 (T2) — target accepts it and stores T2.
  2. Replay initiation 2 (exact same bytes, T2 = T2) — target must reject it.
  3. Send init2_dup (T2, fresh ephemeral/sender_index) — target must reject it (T2 not > T2).
  4. Send initiation 1 (T1 < T2) — target must reject it.
  5. Send initiation 3 (T3 > T2) — target accepts it, confirming it still works.
"""
import time

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget
from black_noise.primitives import wg_timestamp



class TestHandshakeInitTimestampVerification(AbstractTestCase):
    """
    We act as the initiator. We verify that the target rejects both replayed
    and earlier-timestamped initiations, and accepts fresh ones.
    """

    @property
    def name(self) -> str:
        return "handshake_init_timestamp_verification"

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target)

        # Pre-create all packets with 1-second gaps to ensure T1 < T2 < T3.
        session1 = self._new_session(target)
        init_bytes1 = bytes(session1.init_handshake(peer_public_key=target.target_public_key))
        time.sleep(1)

        t2 = wg_timestamp()
        session2 = self._new_session(target)
        init_bytes2 = bytes(session2.init_handshake(peer_public_key=target.target_public_key, timestamp=t2))

        # Fresh ephemeral key and sender_index, but same T2 timestamp value.
        session2_dup = self._new_session(target)
        init_bytes2_dup = bytes(session2_dup.init_handshake(peer_public_key=target.target_public_key, timestamp=t2))
        time.sleep(1)

        # Step 1: Send initiation 2 (T2) — target accepts and stores T2.
        sock.sendto(init_bytes2, (target.target_physical_ip, target.target_wg_port))

        try:
            sock.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, "Did not receive response to initiation 2")

        # Step 2: Replay initiation 2 (exact same bytes, T2 = T2) — must be rejected.
        sock.sendto(init_bytes2, (target.target_physical_ip, target.target_wg_port))
        if report := self._expect_silence(sock, target, "replayed initiation (T2 = T2)"):
            return report

        # Step 3: Send init2_dup (same T2, fresh ephemeral/sender_index) — must be rejected.
        sock.sendto(init_bytes2_dup, (target.target_physical_ip, target.target_wg_port))
        if report := self._expect_silence(sock, target, "fresh initiation with duplicate timestamp (T2 = T2)"):
            return report

        # Step 4: Send initiation 1 (T1 < T2) — must be rejected.
        sock.sendto(init_bytes1, (target.target_physical_ip, target.target_wg_port))
        if report := self._expect_silence(sock, target, "initiation with earlier timestamp (T1 < T2)"):
            return report

        # Step 5: Send a fresh initiation (T3 > T2) — must be accepted, confirming the target still works.
        if report := self._verify_as_initiator(target):
            return report
        return self._pass(target, "Target correctly rejected replayed (T2=T2), duplicate-timestamp (T2=T2 fresh keys), and earlier (T1<T2) initiations, and accepted a fresh one (T3>T2)")
