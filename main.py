import base64
import threading

from wg_server import WgServer, get_public_key_from_private_key, WgPeer


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
