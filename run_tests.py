"""
Entry point for running the test suite against a WireGuard target.

Usage:
    python run_tests.py <target>

    <target> is the name of a subdirectory under targets/, e.g.:
        python run_tests.py wireguard-go-docker-no-endpoint
        python run_tests.py wireguard-go-docker-hardcoded-endpoint

"""
import argparse
import importlib.util
import os
import socket
import subprocess
import sys

from black_noise.TestRunner import TestRunner
from black_noise.TestResult import TestReport, TestStatus
from black_noise.TestTarget import TestTarget
from black_noise.test_cases.test_cookie_initiator import TestCookieInitiator
from black_noise.test_cases.test_cookie_responder import TestCookieResponder
from black_noise.test_cases.test_handshake_init_encrypted_static_key_verification import \
    TestHandshakeInitEncryptedStaticKeyVerification
from black_noise.test_cases.test_handshake_init_encrypted_static_tag_verification import \
    TestHandshakeInitEncryptedStaticTagVerification
from black_noise.test_cases.test_handshake_init_encrypted_timestamp_tag_verification import \
    TestHandshakeInitEncryptedTimestampTagVerification
from black_noise.test_cases.test_handshake_init_ephemeral_key_verification import TestHandshakeInitEphemeralKeyVerification
from black_noise.test_cases.test_handshake_init_timestamp_verification import TestHandshakeInitTimestampVerification
from black_noise.test_cases.test_handshake_init_timestamp_overflow_nanoseconds import TestHandshakeInitTimestampOverflowNanoseconds
from black_noise.test_cases.test_handshake_initiator import TestHandshakeInitiation
from black_noise.test_cases.test_handshake_responder import TestHandshakeResponder
from black_noise.test_cases.test_handshake_response_encrypted_nothing_tag_verification import \
    TestHandshakeResponseEncryptedNothingTagVerification
from black_noise.test_cases.test_handshake_response_ephemeral_all_zeros import TestHandshakeResponseEphemeralAllZeros
from black_noise.test_cases.test_handshake_response_replay import TestHandshakeResponseReplay
from black_noise.test_cases.test_handshake_response_ephemeral_low_order import TestHandshakeResponseEphemeralLowOrder
from black_noise.test_cases.test_handshake_init_mac_1_verification import TestHandshakeInitMac1Verification
from black_noise.test_cases.test_handshake_response_mac_1_verification import TestHandshakeResponseMac1Verification
from black_noise.test_cases.test_roaming_cookie_initiator import TestRoamingCookieInitiator
from black_noise.test_cases.test_roaming_cookie_responder import TestRoamingCookieResponder
from black_noise.test_cases.test_roaming_data_initiator import TestRoamingDataInitiator
from black_noise.test_cases.test_roaming_data_responder import TestRoamingDataResponder
from black_noise.test_cases.test_roaming_initiator import TestRoamingInitiator
from black_noise.test_cases.test_roaming_responder import TestRoamingResponder
from black_noise.test_cases.test_session_expiry import TestSessionExpiry
from black_noise.test_cases.test_transport_counter import TestTransportCounter
from black_noise.test_cases.test_transport_padding import TestTransportPadding
from black_noise.test_cases.test_transport_cryptokey_routing import TestTransportCryptokeyRouting
from black_noise.test_cases.test_handshake_init_reserved_nonzero import TestHandshakeInitReservedNonzero
from black_noise.test_cases.test_unknown_message_type import TestUnknownMessageType


def check_config(target: TestTarget, do_ping_check=True) -> bool:
    """Run pre-flight checks and print results. Returns True if all pass."""
    print("=" * 60)
    print("Config checks")
    print("=" * 60)

    ok = True

    # check: run reset script
    runner = TestRunner(target=target, tests=[])
    reset_error = runner._run_reset_script()
    if reset_error:
        print(f"[ FAIL ] reset script: {reset_error}")
        ok = False

    # Check: bind to both server physical IPs on the WireGuard port.
    for ip in (target.server_physical_ip_1, target.server_physical_ip_2):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind((ip, target.server_wg_port))
            sock.close()
            print(f"[  OK  ] bind {ip}:{target.server_wg_port}")
        except OSError as e:
            print(f"[ FAIL ] bind {ip}:{target.server_wg_port}: {e}")
            ok = False

    if do_ping_check:
        # Check: ping target from both server physical IPs.
        for ip in (target.server_physical_ip_1, target.server_physical_ip_2):
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", "-I", ip, target.target_physical_ip],
                capture_output=True,
            )
            if result.returncode == 0:
                print(f"[  OK  ] ping {target.target_physical_ip} from {ip}")
            else:
                print(f"[ FAIL ] ping {target.target_physical_ip} from {ip}")
                ok = False

    # Check: complete a basic handshake as initiator.
    test = TestHandshakeInitiation()
    try:
        report = test.run_test(target)
    except Exception as e:
        report = TestReport(TestStatus.ERROR, target.name, test.name, str(e))
    if report.status == TestStatus.PASS:
        print(f"[  OK  ] handshake_initiator")
    else:
        suffix = f": {report.message}" if report.message else ""
        label = "FAIL" if report.status == TestStatus.FAIL else "ERROR"
        print(f"[ {label} ] handshake_initiator{suffix}")
        ok = False

    print()
    return ok


def load_target(target_dir: str):
    """Load the TestTarget instance from a target directory's target.py."""
    path = os.path.join(os.path.dirname(__file__), "targets", target_dir, "target.py")
    spec = importlib.util.spec_from_file_location(f"target_{target_dir}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.target


def main():
    parser = argparse.ArgumentParser(description="Run the WireGuard test suite against a target.")
    parser.add_argument("target", help="Target directory name under targets/, e.g. wireguard-go-docker-hardcoded-endpoint")
    parser.add_argument("--skip-config-checks", action="store_true",
                        help="Skip pre-flight config checks and run tests immediately")
    args = parser.parse_args()

    target = load_target(args.target)

    tests = [
        TestHandshakeInitiation(),
        TestHandshakeResponder(),
        TestCookieInitiator(),
        TestCookieResponder(),

        TestHandshakeInitEncryptedStaticTagVerification(),
        TestHandshakeInitEncryptedTimestampTagVerification(),
        TestHandshakeInitMac1Verification(),
        TestHandshakeInitTimestampVerification(),
        TestHandshakeInitTimestampOverflowNanoseconds(),
        TestHandshakeInitEphemeralKeyVerification(),
        TestHandshakeInitEncryptedStaticKeyVerification(),
        TestHandshakeResponseEphemeralAllZeros(),
        TestHandshakeResponseEphemeralLowOrder(),
        TestHandshakeResponseEncryptedNothingTagVerification(),
        TestHandshakeResponseMac1Verification(),
        TestHandshakeResponseReplay(),
        TestRoamingResponder(),
        TestRoamingCookieResponder(),
        TestRoamingDataResponder(),
        TestRoamingInitiator(),
        TestRoamingCookieInitiator(),
        TestRoamingDataInitiator(),
        TestSessionExpiry(),
        TestTransportCounter(),
        TestTransportCryptokeyRouting(),
        TestTransportPadding(),
        TestHandshakeInitReservedNonzero(),
        TestUnknownMessageType(),
    ]

    if not args.skip_config_checks and not check_config(target):
        print("Config checks failed, fix the issues above before running tests.")
        sys.exit(1)

    runner = TestRunner(target=target, tests=tests)
    runner.run_all()


if __name__ == "__main__":
    main()
