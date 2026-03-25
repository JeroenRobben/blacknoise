"""
Entry point for running the test suite against a WireGuard target.

Usage:
    python run_tests.py <target>

    <target> is the name of a subdirectory under targets/, e.g.:
        python run_tests.py wireguard-go
        python run_tests.py wireguard-go-hardcoded-endpoint

"""
import argparse
import importlib.util
import os

from black_noise.TestRunner import TestRunner
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


def load_target(target_dir: str):
    """Load the TestTarget instance from a target directory's target.py."""
    path = os.path.join(os.path.dirname(__file__), "targets", target_dir, "target.py")
    spec = importlib.util.spec_from_file_location(f"target_{target_dir}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.target


def main():
    parser = argparse.ArgumentParser(description="Run the WireGuard test suite against a target.")
    parser.add_argument("target", help="Target directory name under targets/, e.g. wireguard-go")
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
    ]

    runner = TestRunner(target=target, tests=tests)
    runner._run_reset_script()
    runner.run_all()


if __name__ == "__main__":
    main()
