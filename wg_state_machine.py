import random
from typing import Self, Optional

from scapy.contrib.wireguard import *
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

from wg_primitives import *


class InvalidStatePacketError(Exception):
    def __init__(self, state_name: str, packet_type: str):
        self.message = f"Received invalid packet type {packet_type} for state {state_name}"
        super().__init__(self.message)


def calc_mac_1(pkt: Packet, peer_s_pub_key: bytes):
    if type(pkt) == WireguardInitiation:
        offset = 1 + 3 + 4 + 32 + (32 + 16) + (12 + 16)
        message_type = 1
    elif type(pkt) == WireguardResponse:
        offset = 1 + 3 + 4 + 4 + 32 + (0 + 16)
        message_type = 2
    else:
        raise RuntimeError()

    return wg_mac(wg_hash(wg_label_mac1() + peer_s_pub_key), bytes(Wireguard(message_type=message_type) / pkt)[:offset])


def calc_mac_2(pkt: Packet, cookie: bytes):
    if type(pkt) == WireguardInitiation:
        offset = 1 + 3 + 4 + 32 + (32 + 16) + (12 + 16) + 16
        message_type = 1
    elif type(pkt) == WireguardResponse:
        offset = 1 + 3 + 4 + 4 + 32 + (0 + 16) + 16
        message_type = 2
    else:
        raise RuntimeError()

    return wg_mac(cookie, bytes(Wireguard(message_type=message_type) / pkt)[:offset])


def get_fixed_cookie() -> bytes:
    return wg_mac(key=b"cookie", data=b"cookie")


def parse_ip_pkt(pkt_bytes: bytes) -> Packet:
    version = pkt_bytes[0] >> 4
    match version:
        case 4:
            return IP(pkt_bytes)
        case 6:
            return IPv6(pkt_bytes)
        case _:
            raise RuntimeError(f"Unexpected packet IP version: {version}")


class WgSecureSession:
    send_cookie: bool = True

    server_private_key: bytes
    server_public_key: bytes
    server_ephemeral_private_key: bytes
    server_ephemeral_public_key: bytes

    peer_public_key: bytes
    peer_timestamp: bytes | None = None
    preshared_symmetric_key: bytes

    local_session_index: int
    peer_session_index: int

    session_state = None

    def __init__(self, server_private_key: bytes, preshared_symmetric_key=bytes(32)):
        self.session_state = WgStateIdle(self)
        self.local_session_index = random.randint(0, 2 ** 32 - 1)
        self.server_private_key = server_private_key
        self.server_public_key = get_public_key_from_private_key(server_private_key)
        self.preshared_symmetric_key = preshared_symmetric_key
        self.server_ephemeral_private_key, self.server_ephemeral_public_key = wg_dh_generate()

    def handle_packet(self, pkt: Wireguard) -> Optional[Packet]:
        print(f"handling_packet:")
        pkt.show()
        pkt_reply = None

        match pkt.payload:
            case WireguardInitiation() as p:
                self.session_state, pkt_reply = self.session_state.handle_hs_initiation(p)
            case WireguardResponse() as p:
                self.session_state, pkt_reply = self.session_state.handle_hs_response(p)
            case WireguardCookieReply() as p:
                self.session_state, pkt_reply = self.session_state.handle_cookie_reply(p)
            case WireguardTransport() as p:
                self.session_state, pkt_reply = self.session_state.decapsulate_transport_data(p)
            case _:
                return None

        match pkt_reply:
            case WireguardInitiation():
                return Wireguard(message_type=1) / pkt_reply
            case WireguardResponse():
                return Wireguard(message_type=2) / pkt_reply
            case WireguardCookieReply():
                return Wireguard(message_type=3) / pkt_reply
            case WireguardTransport():
                return Wireguard(message_type=4) / pkt_reply
            case IP() | IPv6():
                return pkt_reply
            case _:
                return None

    def init_handshake(self, peer_public_key: bytes) -> Wireguard:
        if type(self.session_state) is WgStateIdle:
            self.peer_public_key = peer_public_key

            session_state: WgStateIdle = self.session_state
            self.session_state, pkt_reply = session_state.do_hs_initiation()
            return Wireguard(message_type=1) / pkt_reply
        else:
            raise RuntimeError("init_handshake called when state isn't WgStateIdle")

    def encapsulate_transport_data(self, pkt: bytes) -> Wireguard:
        if self.can_encapsulate_transport_data():
            new_state, pkt_reply = self.session_state.encapsulate_transport_data(pkt)
            self.session_state = new_state
            return Wireguard(message_type=4) / pkt_reply
        raise RuntimeError(f"Can not send transport data in state {self.session_state.state_name}")

    def can_encapsulate_transport_data(self) -> bool:
        return type(self.session_state) is WgStateActiveInitiator or type(self.session_state) is WgStateActiveResponder


class WgState:
    session: WgSecureSession = None

    def __init__(self, state_name, session):
        self.state_name = state_name
        self.session = session

    def handle_hs_initiation(self, wg_pkt: WireguardInitiation) -> tuple[Self, Wireguard]:
        raise InvalidStatePacketError(self.state_name, wg_pkt.name)

    def handle_hs_response(self, wg_pkt: WireguardResponse) -> tuple[Self, Wireguard]:
        raise InvalidStatePacketError(self.state_name, wg_pkt.name)

    def handle_cookie_reply(self, wg_pkt: WireguardCookieReply) -> tuple[Self, Wireguard]:
        raise InvalidStatePacketError(self.state_name, wg_pkt.name)

    def decapsulate_transport_data(self, wg_pkt: WireguardTransport) -> tuple[Self, Optional[IP | IPv6]]:
        raise InvalidStatePacketError(self.state_name, wg_pkt.name)

    def encapsulate_transport_data(self, transport_data_bytes: bytes):
        raise InvalidStatePacketError(self.state_name, "IP/IPV6")


class WgStateIdle(WgState):
    def __init__(self, session):
        super().__init__("idle", session)

    def handle_hs_initiation(self, wg_pkt: WireguardInitiation) -> tuple[WgState, Packet]:
        s_priv_r = self.session.server_private_key
        s_pub_r = self.session.server_public_key
        e_pub_i = wg_pkt.unencrypted_ephemeral
        self.session.peer_session_index = wg_pkt.sender_index

        if self.session.send_cookie and wg_pkt.mac2 == bytes(16):
            pkt_cookie = WireguardCookieReply()
            pkt_cookie.receiver_index = wg_pkt.sender_index
            pkt_cookie.nonce = bytes(24)
            t = get_fixed_cookie()
            key = wg_hash(wg_label_cookie() + s_pub_r)
            pkt_cookie.encrypted_cookie = wg_xaead_encrypt(key=key, nonce=bytes(24), plain_text=t,
                                                           auth_text=wg_pkt.mac1)
            return self, pkt_cookie
        elif self.session.send_cookie:  # Mac2 set
            if wg_pkt.mac2 != calc_mac_2(wg_pkt, cookie=get_fixed_cookie()):
                raise ValueError("Invalid mac2")
            print("Mac2 valid")

        c_r = wg_hash(wg_construction())
        h_r = wg_hash(c_r + wg_identifier())
        h_r = wg_hash(h_r + s_pub_r)
        c_r = wg_kdf(c_r, e_pub_i, 1)
        h_r = wg_hash(h_r + e_pub_i)
        c_r, k = wg_kdf(c_r, wg_dh(s_priv_r, e_pub_i), 2)
        s_pub_i = wg_aead_decrypt(k, 0, wg_pkt.encrypted_static, h_r)

        self.session.peer_public_key = s_pub_i
        if calc_mac_1(wg_pkt, s_pub_r) != wg_pkt.mac1:
            raise ValueError("Invalid mac1")
        print("Mac1 valid")

        q = self.session.preshared_symmetric_key

        h_r = wg_hash(h_r + wg_pkt.encrypted_static)
        c_r, k = wg_kdf(c_r, wg_dh(s_priv_r, s_pub_i), 2)
        timestamp = wg_aead_decrypt(k, 0, wg_pkt.encrypted_timestamp, h_r)
        self.session.peer_timestamp = timestamp

        h_r = wg_hash(h_r + wg_pkt.encrypted_timestamp)

        pkt_reply = WireguardResponse()
        pkt_reply.sender_index = self.session.local_session_index
        pkt_reply.receiver_index = self.session.peer_session_index

        e_priv_r, e_pub_r = wg_dh_generate()
        c_r = wg_kdf(c_r, e_pub_r, 1)
        pkt_reply.unencrypted_ephemeral = e_pub_r
        h_r = wg_hash(h_r + e_pub_r)
        c_r = wg_kdf(c_r, wg_dh(e_priv_r, e_pub_i), 1)
        c_r = wg_kdf(c_r, wg_dh(e_priv_r, s_pub_i), 1)
        c_r, t, k = wg_kdf(c_r, q, 3)
        h_r = wg_hash(h_r + t)
        pkt_reply.encrypted_nothing = wg_aead_encrypt(k, 0, b'', h_r)
        h_r = wg_hash(h_r + pkt_reply.encrypted_nothing)

        t_recv_r, t_send_r = wg_kdf(c_r, b'', 2)
        print(f't_recv_r: {t_recv_r}, t_send_r: {t_send_r}')

        pkt_reply.mac1 = calc_mac_1(pkt_reply, self.session.peer_public_key)

        new_state = WgStateResponseSent(session=self.session, t_recv_r=t_recv_r, t_send_r=t_send_r,
                                        wg_pkt_response=pkt_reply)
        return new_state, pkt_reply

    def do_hs_initiation(self) -> tuple[WgState, WireguardInitiation]:
        s_pub_r = self.session.peer_public_key
        s_pub_i = self.session.server_public_key
        s_priv_i = self.session.server_private_key
        e_priv_i = self.session.server_ephemeral_private_key
        e_pub_i = self.session.server_ephemeral_public_key

        pkt: WireguardInitiation = WireguardInitiation()
        pkt.sender_index = self.session.local_session_index

        c_i = wg_hash(wg_construction())
        h_i = wg_hash(c_i + wg_identifier())
        h_i = wg_hash(h_i + s_pub_r)
        c_i = wg_kdf(c_i, e_pub_i, 1)
        pkt.unencrypted_ephemeral = e_pub_i
        h_i = wg_hash(h_i + e_pub_i)
        c_i, k = wg_kdf(c_i, wg_dh(e_priv_i, s_pub_r), 2)
        pkt.encrypted_static = wg_aead_encrypt(k, 0, s_pub_i, h_i)
        h_i = wg_hash(h_i + pkt.encrypted_static)
        c_i, k = wg_kdf(c_i, wg_dh(s_priv_i, s_pub_r), 2)
        pkt.encrypted_timestamp = wg_aead_encrypt(k, 0, wg_timestamp(), h_i)
        h_i = wg_hash(h_i + pkt.encrypted_timestamp)

        pkt.mac1 = calc_mac_1(pkt, self.session.peer_public_key)

        new_state = WgStateInitSent(session=self.session, c_i=c_i, h_i=h_i,
                                    wg_pkt_initiation=pkt)

        return new_state, pkt


class WgStateInitSent(WgState):
    def __init__(self, session, h_i: bytes, c_i: bytes,
                 wg_pkt_initiation: WireguardInitiation):
        super().__init__("init_sent", session)
        self.h_i = h_i
        self.c_i = c_i
        self.wg_pkt_initiation = wg_pkt_initiation

    def handle_hs_response(self, wg_pkt: WireguardResponse) -> tuple[WgState, Wireguard]:
        h_i = self.h_i
        c_i = self.c_i
        q = self.session.preshared_symmetric_key
        s_pub_i = self.session.server_public_key
        e_priv_i = self.session.server_ephemeral_private_key
        s_priv_i = self.session.server_private_key

        if self.session.send_cookie and wg_pkt.mac2 == bytes(16):
            pkt_cookie = WireguardCookieReply()
            pkt_cookie.receiver_index = wg_pkt.sender_index
            pkt_cookie.nonce = bytes(24)
            t = get_fixed_cookie()
            key = wg_hash(wg_label_cookie() + s_pub_i)
            pkt_cookie.encrypted_cookie = wg_xaead_encrypt(key=key, nonce=bytes(24),
                                                           plain_text=t, auth_text=wg_pkt.mac1)
            return self, pkt_cookie
        elif self.session.send_cookie:  # Mac2 set
            if wg_pkt.mac2 != calc_mac_2(wg_pkt, cookie=get_fixed_cookie()):
                raise ValueError("Invalid mac2")
            print("Mac2 valid")

        if calc_mac_1(wg_pkt, self.session.server_public_key) != wg_pkt.mac1:
            raise ValueError("Invalid mac1")
        print("Mac1 valid")

        e_pub_r = wg_pkt.unencrypted_ephemeral
        c_i = wg_kdf(c_i, e_pub_r, 1)
        h_i = wg_hash(h_i + e_pub_r)
        c_i = wg_kdf(c_i, wg_dh(e_priv_i, e_pub_r), 1)
        c_i = wg_kdf(c_i, wg_dh(s_priv_i, e_pub_r), 1)
        c_i, t, k = wg_kdf(c_i, q, 3)
        h_i = wg_hash(h_i + t)
        encrypted_nothing = wg_aead_decrypt(key=k, counter=0, cipher_text_with_tag=wg_pkt.encrypted_nothing,
                                            auth_text=h_i)
        assert (len(encrypted_nothing) == 0)
        h_i = wg_hash(h_i + wg_pkt.encrypted_nothing)

        t_send_i, t_recv_i = wg_kdf(c_i, b'', 2)

        self.session.peer_session_index = wg_pkt.sender_index
        new_state = WgStateActiveInitiator(session=self.session, t_recv_i=t_recv_i, t_send_i=t_send_i, ctr_send=0,
                                           ctr_recv=0)

        pkt_keepalive = WireguardTransport()
        pkt_keepalive.receiver_index = wg_pkt.sender_index
        pkt_keepalive.counter = 0
        pkt_keepalive.encrypted_encapsulated_packet = wg_aead_encrypt(key=t_send_i, counter=0, plain_text=b'',
                                                                      auth_text=b'')

        return new_state, pkt_keepalive

    def handle_cookie_reply(self, wg_cookie_reply: WireguardCookieReply) -> tuple[WgState, Wireguard]:
        nonce = wg_cookie_reply.nonce
        encrypted_cookie = wg_cookie_reply.encrypted_cookie
        key = wg_hash(wg_label_cookie() + self.session.peer_public_key)
        cookie = wg_xaead_decrypt(key=key, nonce=nonce, cipher_text_with_tag=encrypted_cookie,
                                  auth_text=bytes(Wireguard(message_type=1) / self.wg_pkt_initiation))

        reply_pkt = self.wg_pkt_initiation
        reply_pkt.mac2 = calc_mac_2(pkt=reply_pkt, cookie=cookie)

        return self, reply_pkt


class WgStateResponseSent(WgState):
    def __init__(self, session, t_recv_r: bytes, t_send_r: bytes, wg_pkt_response: WireguardResponse):
        super().__init__("response_sent", session)
        self.t_recv_r = t_recv_r
        self.t_send_r = t_send_r
        self.wg_pkt_response = wg_pkt_response

    def handle_cookie_reply(self, wg_cookie_reply: WireguardCookieReply) -> tuple[WgState, Wireguard]:
        nonce = wg_cookie_reply.nonce
        encrypted_cookie = wg_cookie_reply.encrypted_cookie
        key = wg_hash(wg_label_cookie() + self.session.peer_public_key)
        cookie = wg_xaead_decrypt(key=key, nonce=nonce, cipher_text_with_tag=encrypted_cookie,
                                  auth_text=bytes(Wireguard(message_type=2) / self.wg_pkt_response))

        reply_pkt = self.wg_pkt_response
        reply_pkt.mac2 = calc_mac_2(pkt=reply_pkt, cookie=cookie)

        return self, reply_pkt

    def decapsulate_transport_data(self, wg_pkt: WireguardTransport) -> tuple[WgState, Optional[IP | IPv6]]:
        counter = wg_pkt.counter
        encrypted_packet = wg_pkt.encrypted_encapsulated_packet
        decrypted_packet_bytes = wg_aead_decrypt(key=self.t_recv_r, counter=counter,
                                                 cipher_text_with_tag=encrypted_packet, auth_text=bytes())

        new_state = WgStateActiveResponder(session=self.session, t_recv_r=self.t_recv_r, t_send_r=self.t_send_r,
                                           ctr_send=0, ctr_recv=1)

        if len(decrypted_packet_bytes) != 0:
            inner_pkt = parse_ip_pkt(decrypted_packet_bytes)
            print(f"Inner packet: {inner_pkt.summary()}")
            return new_state, inner_pkt
        return new_state, None


class WgStateActiveResponder(WgState):
    def __init__(self, session, t_recv_r: bytes, t_send_r: bytes, ctr_send: int, ctr_recv: int):
        super().__init__("active_responder", session)
        self.t_recv_r = t_recv_r
        self.t_send_r = t_send_r
        self.ctr_send = ctr_send
        self.ctr_recv = ctr_recv

    def decapsulate_transport_data(self, wg_pkt: WireguardTransport) -> tuple[WgState, Optional[IP | IPv6]]:
        counter = wg_pkt.counter
        encrypted_packet = wg_pkt.encrypted_encapsulated_packet
        decrypted_packet_bytes = wg_aead_decrypt(key=self.t_recv_r, counter=counter,
                                                 cipher_text_with_tag=encrypted_packet, auth_text=bytes())

        if len(decrypted_packet_bytes) != 0:
            inner_pkt = parse_ip_pkt(decrypted_packet_bytes)
            print(f"Inner packet: {inner_pkt.summary()}")
            return self, inner_pkt

        return self, None

    def encapsulate_transport_data(self, transport_data_bytes: bytes) -> tuple[WgState, Wireguard]:
        pkt = WireguardTransport()
        pkt.receiver_index = self.session.peer_session_index
        pkt.counter = self.ctr_send
        pkt.encrypted_encapsulated_packet = wg_aead_encrypt(key=self.t_send_r, counter=self.ctr_send,
                                                            plain_text=transport_data_bytes, auth_text=b'')

        new_state = WgStateActiveResponder(session=self.session, t_recv_r=self.t_recv_r, t_send_r=self.t_send_r,
                                           ctr_send=self.ctr_send + 1, ctr_recv=self.ctr_recv)
        return new_state, pkt


class WgStateActiveInitiator(WgState):
    def __init__(self, session, t_recv_i: bytes, t_send_i: bytes, ctr_send: int, ctr_recv: int):
        super().__init__("active_initiator", session)
        self.t_recv_i = t_recv_i
        self.t_send_i = t_send_i
        self.ctr_send = ctr_send
        self.ctr_recv = ctr_recv

    def decapsulate_transport_data(self, wg_pkt: WireguardTransport) -> tuple[WgState, Optional[IP | IPv6]]:
        counter = wg_pkt.counter
        encrypted_packet = wg_pkt.encrypted_encapsulated_packet
        decrypted_packet_bytes = wg_aead_decrypt(key=self.t_recv_i, counter=counter,
                                                 cipher_text_with_tag=encrypted_packet, auth_text=bytes())

        if len(decrypted_packet_bytes) != 0:
            inner_pkt = parse_ip_pkt(decrypted_packet_bytes)
            print(f"Inner packet: {inner_pkt.summary()}")
            return self, inner_pkt

        return self, None

    def encapsulate_transport_data(self, transport_data_bytes: bytes) -> tuple[WgState, Wireguard]:
        pkt = WireguardTransport()
        pkt.receiver_index = self.session.peer_session_index
        pkt.counter = self.ctr_send
        pkt.encrypted_encapsulated_packet = wg_aead_encrypt(key=self.t_send_i, counter=self.ctr_send,
                                                            plain_text=transport_data_bytes, auth_text=b'')

        new_state = WgStateActiveInitiator(session=self.session, t_recv_i=self.t_recv_i, t_send_i=self.t_send_i,
                                           ctr_send=self.ctr_send + 1, ctr_recv=self.ctr_recv)
        return new_state, pkt


class WgStateExpired(WgState):
    def __init__(self, session):
        super().__init__("expired", session)
