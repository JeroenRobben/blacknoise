"""
Test: verify that the target correctly pads transport data packets to a
multiple of 16 bytes.

The WireGuard spec requires the plaintext inside each transport packet to be
padded to the next multiple of 16 bytes before AEAD encryption. This means the
ciphertext length (padded plaintext + 16-byte Poly1305 tag) must always be a
multiple of 16.

We act as the initiator, establish a session, then send UDP echo requests with
payload sizes 0–16 through the tunnel. For each echo reply we verify:
  1. The ciphertext length (encrypted_encapsulated_packet) is a multiple of 16.
  2. If padding was needed, the decrypted packet has a Padding layer whose
     length matches the expected padding (derived from len(pkt_echo) % 16)
     and whose content is all-zero bytes.

IP (20) + UDP (8) = 28 bytes of overhead, so sizes 0–16 produce IP packets
of 28–44 bytes, covering all 16 possible mod-16 residues.
"""
import socket

from scapy.contrib.wireguard import Wireguard, WireguardTransport
from scapy.layers.inet import IP, UDP
from scapy.packet import Padding, Raw

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport
from black_noise.TestTarget import TestTarget
from black_noise.state_machine import WgStateActiveInitiator



class TestTransportPadding(AbstractTestCase):
    """
    We act as the initiator. For each payload size 0–16 we send an echo
    request and verify that the target's transport reply is padded correctly.
    """

    @property
    def name(self) -> str:
        return "transport_padding"

    def run_test(self, target: TestTarget) -> TestReport:
        sock, _ = self._open_sockets(target)

        # Establish session as initiator.
        session = self._new_session(target)
        init_pkt = session.init_handshake(peer_public_key=target.target_public_key)
        sock.sendto(bytes(init_pkt), (target.target_physical_ip, target.target_wg_port))

        try:
            pkt_bytes, _ = sock.recvfrom(65535)
        except socket.timeout:
            return self._fail(target, "Target did not respond to handshake initiation")

        pkt_keepalive = session.handle_packet(Wireguard(pkt_bytes))
        if not isinstance(session.session_state, WgStateActiveInitiator):
            return self._fail(target, "Handshake did not complete into an active session")

        sock.sendto(bytes(pkt_keepalive), (target.target_physical_ip, target.target_wg_port))

        for size in range(17):  # 0 through 16 inclusive
            payload = b"A" * size
            pkt_echo = IP(src=target.server_wg_ip, dst=target.target_wg_ip) / UDP(sport=target.echo_port, dport=target.echo_port)
            if payload:
                pkt_echo = pkt_echo / Raw(load=payload)
            sock.sendto(bytes(session.encapsulate_transport_data(bytes(pkt_echo))),
                        (target.target_physical_ip, target.target_wg_port))

            try:
                pkt_bytes, _ = sock.recvfrom(65535)
            except socket.timeout:
                return self._fail(target, f"No echo reply for payload size {size}")

            wg_pkt = Wireguard(pkt_bytes)
            enc_len = len(wg_pkt[WireguardTransport].encrypted_encapsulated_packet)
            if enc_len % 16 != 0:
                return self._fail(target,
                    f"Payload size {size}: ciphertext length {enc_len} is not a multiple of 16")

            echo_reply = session.handle_packet(wg_pkt)
            if echo_reply is None:
                return self._fail(target, f"Payload size {size}: could not decrypt echo reply")

            reply_payload = bytes(echo_reply[Raw].load) if echo_reply.haslayer(Raw) else b''
            if reply_payload != payload:
                return self._fail(target,
                    f"Payload size {size}: echo payload mismatch (got {reply_payload!r})")

            expected_padding = (16 - len(bytes(pkt_echo)) % 16) % 16
            if expected_padding > 0:
                if not echo_reply.haslayer(Padding):
                    return self._fail(target,
                        f"Payload size {size}: expected {expected_padding} padding bytes but no Padding layer found")
                pad_load = bytes(echo_reply[Padding].load)
                if len(pad_load) != expected_padding:
                    return self._fail(target,
                        f"Payload size {size}: expected {expected_padding} padding bytes, got {len(pad_load)}")
                if pad_load != b'\x00' * expected_padding:
                    return self._fail(target,
                        f"Payload size {size}: padding is not all-zero: {pad_load!r}")
            else:
                if echo_reply.haslayer(Padding) and len(bytes(echo_reply[Padding].load)) > 0:
                    return self._fail(target,
                        f"Payload size {size}: unexpected padding bytes found")

        return self._pass(target, "All 17 transport packets correctly padded to a multiple of 16 bytes")
