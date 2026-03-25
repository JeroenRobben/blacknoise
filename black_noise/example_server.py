import base64
import fcntl
import ipaddress

from scapy.all import *
from scapy.contrib.wireguard import *
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

from .primitives import *
from .state_machine import WgSecureSession


class WgPeer:
    peer_public_key: bytes
    preshared_symmetric_key: bytes = bytes(32)
    allowed_subnets: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
    session: WgSecureSession = None

    def __init__(self, peer_public_key: bytes, remote_ip: str, remote_port: int, allowed_subnets_str: list[str],
                 preshared_key: bytes | None = None):
        ip = ipaddress.ip_address(remote_ip)
        if isinstance(ip, ipaddress.IPv4Address):
            ip_str = str(ip.ipv6_mapped)
        else:
            ip_str = remote_ip

        self.allowed_subnets = []
        for subnet in allowed_subnets_str:
            self.allowed_subnets.append(ipaddress.ip_network(subnet))

        self.peer_public_key = peer_public_key
        self.remote_ip = ip_str
        self.remote_port = remote_port
        if preshared_key is not None:
            self.preshared_symmetric_key = preshared_key

    def is_session_active(self) -> bool:
        return self.session is not None and self.session.can_encapsulate_transport_data()

    def __str__(self):
        return f"Peer: public_key={self.peer_public_key}, preshared_symmetric_key={self.preshared_symmetric_key}, allowed_subnets={self.allowed_subnets}"

    def init_handshake(self, server_private_key: bytes) -> Wireguard:
        session = WgSecureSession(server_private_key=server_private_key,
                                  preshared_symmetric_key=self.preshared_symmetric_key)
        self.session = session
        return session.init_handshake(peer_public_key=self.peer_public_key)


class WgServer:
    server_private_key: bytes
    server_public_key: bytes
    peers: list[WgPeer]
    sock: socket.socket
    tun_fd: int
    tun_name: str

    def __init__(self, server_private_key: bytes, server_port: int, tun_name: str, tun_ipv4_with_prefix: str,
                 tun_ipv6_with_prefix: str):
        self.peers = []
        self.server_private_key = server_private_key
        self.server_public_key = get_public_key_from_private_key(server_private_key)

        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        self.sock.bind(("::", server_port))
        self.setup_tun(tun_name, tun_ipv4_with_prefix, tun_ipv6_with_prefix)

    def setup_tun(self, name: str, ipv4_with_prefix: str, ipv6_with_prefix):
        TUNSETIFF = 0x400454ca
        IFF_TUN = 0x0001
        IFF_NO_PI = 0x1000

        self.tun_fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack("16sH", name.encode("UTF-8"), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self.tun_fd, TUNSETIFF, ifr)
        self.tun_name = name

        subprocess.run(["ip", "link", "set", "dev", name, "up"])
        subprocess.run(["ip", "addr", "add", ipv4_with_prefix, "dev", name])
        subprocess.run(["ip", "addr", "add", ipv6_with_prefix, "dev", name])

    def add_peer(self, peer: WgPeer):
        self.peers.append(peer)
        for network in peer.allowed_subnets:
            print(f"Adding route for {network} via {self.tun_name}")
            subprocess.run(["ip", "route", "add", str(network), "dev", self.tun_name], check=False)

    def send_packet_to_peer(self, remote_ip: str, remote_port: int, pkt: Packet):
        print(f"Sending pkt to {remote_ip}:{remote_port}")
        pkt.show()
        self.sock.sendto(bytes(pkt), (remote_ip, remote_port))

    def write_to_tun(self, pkt: IP | IPv6):
        print(f"Writing to tun: {pkt.summary()}")
        # os.write(self.tun_fd, bytes(pkt))

    def stop(self):
        self._stopped = True
        self.sock.close()

    def recv_loop(self):
        self._stopped = False
        while not self._stopped:
            try:
                readable, _, _ = select.select([self.sock, self.tun_fd], [], [])
            except OSError:
                break  # socket was closed by stop()

            for fd in readable:
                if fd is self.sock:
                    data, addr = self.sock.recvfrom(65536)
                    self.handle_packet_from_peer(pkt_bytes=data, remote_ip=addr[0], remote_port=addr[1])
                elif fd is self.tun_fd:
                    pkt = os.read(self.tun_fd, 65536)
                    self.handle_packet_from_tun(pkt=pkt)

    def find_peer_by_public_key(self, peer_public_key: bytes) -> WgPeer | None:
        for peer in self.peers:
            if peer.peer_public_key == peer_public_key:
                return peer
        return None

    def find_peer_by_allowed_ip(self, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> WgPeer | None:
        for peer in self.peers:
            for network in peer.allowed_subnets:
                if ip_obj in network:
                    return peer
        return None

    def find_session_by_index(self, session_index: bytes):
        for peer in self.peers:
            if peer.session is not None and peer.session.local_session_index == session_index:
                return peer.session
        return None

    def handle_packet_from_peer(self, pkt_bytes: bytes, remote_ip: str, remote_port: int):
        pkt: Wireguard = Wireguard(pkt_bytes)
        if type(pkt.payload) is WireguardInitiation:
            session = WgSecureSession(server_private_key=self.server_private_key)
            reply = session.handle_packet(pkt)
            peer = self.find_peer_by_public_key(session.peer_public_key)
            if peer is None:
                raise ValueError(f"Could not find peer with public key {base64.b64encode(session.peer_public_key)}")
            peer.session = session
        else:
            session_index = pkt.receiver_index
            session = self.find_session_by_index(session_index=session_index)
            peer = self.find_peer_by_public_key(peer_public_key=session.peer_public_key)
            if session is None:
                raise ValueError(f"Could not find session with index {session_index}")
            reply = session.handle_packet(pkt)

        peer.remote_ip = remote_ip
        peer.remote_port = remote_port

        if type(reply) is Wireguard:
            self.send_packet_to_peer(remote_ip=remote_ip, remote_port=remote_port, pkt=reply)
        elif type(reply) is IP or type(reply) is IPv6:
            self.write_to_tun(pkt=reply)

    def handle_packet_from_tun(self, pkt: bytes):
        version = pkt[0] >> 4

        match version:
            case 4:
                dst_ip = ipaddress.IPv4Address(pkt[16:20])
            case 6:
                dst_ip = ipaddress.IPv6Address(pkt[24:40])
            case _:
                raise ValueError(f"Invalid IP packet read from tun")

        peer = self.find_peer_by_allowed_ip(dst_ip)
        if peer and peer.session and peer.session.can_encapsulate_transport_data():
            reply = peer.session.encapsulate_transport_data(pkt)
            self.send_packet_to_peer(remote_ip=peer.remote_ip, remote_port=peer.remote_port, pkt=reply)

        elif peer:
            print(f"Packet for {dst_ip} dropped: No active session for peer {peer}, handshake initiated")
            self.init_handshake(peer)
        else:
            print(f"Packet for {dst_ip} dropped: No peer found for this IP")

    def init_handshake(self, peer: WgPeer):
        if peer not in self.peers:
            raise RuntimeError(f"Peer {peer} not yet added to server")
        reply = peer.init_handshake(server_private_key=self.server_private_key)
        self.send_packet_to_peer(remote_ip=peer.remote_ip, remote_port=peer.remote_port, pkt=reply)


def test_self():
    server_private_key = base64.b64decode("wEGkbr9eQnkHsL4vF6OwS7+l4O0z0cyOrc/9/T+p5Fs=")
    peer_private_key = base64.b64decode("wEGkbr9eQnkHsL4vF6OwS7+l4O0z0cyOrc/9/T+p5Fs=")
    peer_public_key = get_public_key_from_private_key(peer_private_key)

    server_1 = WgServer(server_private_key=server_private_key, server_port=51820, tun_ipv4_with_prefix="10.8.0.1/32",
                        tun_ipv6_with_prefix="fd42::1/128", tun_name="tun-wg-0")
    server_2 = WgServer(server_private_key=server_private_key, server_port=51821, tun_ipv4_with_prefix="10.8.0.2/32",
                        tun_ipv6_with_prefix="fd42::2/128", tun_name="tun-wg-1")

    peer_server_1 = WgPeer(peer_public_key=peer_public_key, remote_ip="127.0.0.1", remote_port=51820,
                           allowed_subnets_str=["10.0.2.0/24"])
    peer_server_2 = WgPeer(peer_public_key=peer_public_key, remote_ip="127.0.0.1", remote_port=51821,
                           allowed_subnets_str=["10.0.3.0/24"])
    server_1.add_peer(peer_server_2)
    server_2.add_peer(peer_server_1)

    server_1.init_handshake(peer_server_2)

    thread1 = threading.Thread(target=server_1.recv_loop)
    thread2 = threading.Thread(target=server_2.recv_loop)

    thread1.start()
    thread2.start()

    thread1.join()
    thread2.join()


def main():
    server_private_key = base64.b64decode("GNLngngd39Ze/IARYa09ae0tKFBEF6OWKxXqOARbIU0=")
    peer_public_key = base64.b64decode("n3K7CddVLicgdqJYmSNEbBUXwe93h8hlz3tPpRhCfEI=")

    server_public_key = get_public_key_from_private_key(server_private_key)
    print(f"Server public key: {base64.b64encode(server_public_key)}")

    server = WgServer(server_private_key=server_private_key, server_port=51820, tun_ipv4_with_prefix="10.8.0.1/32",
                      tun_ipv6_with_prefix="fd42::1/128", tun_name="tun-wg-0")

    peer = WgPeer(peer_public_key=peer_public_key, remote_ip="127.0.0.1", remote_port=51821,
                  allowed_subnets_str=["10.0.3.0/24"])
    server.add_peer(peer)

    server.init_handshake(peer)

    server.recv_loop()


if __name__ == "__main__":
    main()
    # test_self()
