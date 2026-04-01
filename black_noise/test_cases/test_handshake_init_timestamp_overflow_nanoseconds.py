"""
Test: TAI64N timestamp with nanoseconds field exceeding 10^9.

TAI64N encodes time as 8-byte big-endian seconds + 4-byte big-endian nanoseconds.
Valid nanoseconds range is 0–999_999_999. The WireGuard whitepaper states the
timestamp is simply a per-peer monotonically increasing 96-bit number, so
comparison should be done on the raw bytes (big-endian) without normalization.

If an implementation normalizes the nanoseconds field by carrying the overflow
into the seconds field before storing (e.g. (T, 2_000_000_000) → (T+2, 0)),
a subsequent initiation with timestamp (T+1, 0) will appear older than the
stored value and be incorrectly rejected — even though (T+1, 0) is strictly
greater than (T, 2_000_000_000) in raw big-endian byte order.

Test sequence:
  1. Send initiation with ts_base = (T, 0) — accepted, sets the stored timestamp.
  2. Send initiation with ts_invalid = (T, 2_000_000_000) — ns = 2×10^9.
     - ts_invalid > ts_base in raw byte order (same seconds, larger nanoseconds).
     - If rejected: target validates the nanosecond range; no normalization bug
       is possible. Verify liveness and pass.
     - If accepted: target stored either (T, 2e9) raw or normalised (T+2, 0).
  3. Send initiation with ts_middle = (T+1, 0):
     - Raw comparison: (T+1) seconds > T seconds → strictly greater → accept.
     - Normalised comparison: stored (T+2, 0) > (T+1, 0) → incorrectly rejects.
     - FAIL if the target rejects ts_middle.
  4. Liveness check via _verify_as_initiator().
"""
import socket

from pwnlib.util.packing import p32, p64

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget


def _make_ts(seconds: int, nanoseconds: int) -> bytes:
    return p64(seconds, endianness='big') + p32(nanoseconds, endianness='big')


class TestHandshakeInitTimestampOverflowNanoseconds(AbstractTestCase):
    """
    Sends a handshake initiation whose nanoseconds field exceeds 10^9, then
    verifies that a subsequent initiation with a strictly greater raw timestamp
    (but a timestamp that would appear older if normalised) is still accepted.
    """

    @property
    def name(self) -> str:
        return "handshake_init_timestamp_overflow_nanoseconds"

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target)

        T = 1000
        ts_base    = _make_ts(T,     0)
        ts_invalid = _make_ts(T,     2_000_000_000)  # ns = 2×10^9; normalised: (T+2, 0)
        ts_middle  = _make_ts(T + 1, 0)              # raw > ts_invalid; normalised < (T+2, 0)

        # Step 1: establish baseline — target accepts ts_base and stores it.
        session = self._new_session(target)
        sock.sendto(
            bytes(session.init_handshake(peer_public_key=target.target_public_key, timestamp=ts_base)),
            (target.target_physical_ip, target.target_wg_port),
        )
        try:
            sock.recvfrom(65535)
        except socket.timeout:
            return self._error(target, "No response to baseline initiation (ts_base)")
        self._drain(sock)

        # Step 2: send initiation with ts_invalid (ns = 2×10^9).
        session = self._new_session(target)
        sock.sendto(
            bytes(session.init_handshake(peer_public_key=target.target_public_key, timestamp=ts_invalid)),
            (target.target_physical_ip, target.target_wg_port),
        )
        try:
            sock.recvfrom(65535)
            invalid_accepted = True
        except socket.timeout:
            invalid_accepted = False
        self._drain(sock)

        if not invalid_accepted:
            # Target rejected the out-of-range nanosecond value outright.
            # No normalisation possible; verify liveness and pass.
            if report := self._verify_as_initiator(target):
                return self._error(
                    target,
                    "Target rejected ts_invalid but liveness check also failed. Target may have crashed.",
                )
            return self._pass(
                target,
                "Target rejected the out-of-range nanosecond timestamp, no normalisation bug possible",
            )

        # Step 3: send ts_middle = (T+1, 0).
        # Raw bytes: (T+1) > T → strictly greater than ts_invalid → must accept.
        # If target normalised ts_invalid to (T+2, 0) it will incorrectly reject ts_middle.
        session = self._new_session(target)
        sock.sendto(
            bytes(session.init_handshake(peer_public_key=target.target_public_key, timestamp=ts_middle)),
            (target.target_physical_ip, target.target_wg_port),
        )
        try:
            sock.recvfrom(65535)
        except socket.timeout:
            return self._fail(
                target,
                "Target rejected ts_middle=(T+1, 0) after accepting ts_invalid=(T, 2e9): "
                "target likely normalised the stored timestamp to (T+2, 0) and then "
                "incorrectly rejected (T+1, 0) as not strictly greater",
            )
        self._drain(sock)

        # Step 4: liveness check.
        if report := self._verify_as_initiator(target):
            return report

        return self._pass(
            target,
            "Target accepted ts_middle=(seconds+1, 0) after ts_invalid=(seconds, 2e9): "
            "raw big-endian comparison used, no normalisation bug detected",
        )
