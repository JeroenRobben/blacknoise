import hashlib
import hmac
import time

from Crypto.Cipher import ChaCha20_Poly1305
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from pwnlib.util.packing import p64, p32


def wg_dh(private_key_bytes: bytes, public_key_bytes: bytes):
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
    public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)

    shared_secret = private_key.exchange(public_key)
    return shared_secret


def wg_dh_generate() -> tuple[bytes, bytes]:
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return private_bytes, public_bytes


def wg_aead_encrypt(key: bytes, counter: int, plain_text: bytes, auth_text: bytes) -> bytes:
    nonce = bytes(4) + p64(counter, endianness='little')
    aead = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    aead.update(auth_text)
    cipher_text, tag = aead.encrypt_and_digest(plaintext=plain_text)
    return cipher_text + tag


def wg_xaead_encrypt(key: bytes, nonce: bytes, plain_text: bytes, auth_text: bytes) -> bytes:
    aead = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    aead.update(auth_text)
    cipher_text, tag = aead.encrypt_and_digest(plaintext=plain_text)
    return cipher_text + tag


def wg_aead_decrypt(key: bytes, counter: int, cipher_text_with_tag: bytes, auth_text: bytes) -> bytes:
    cipher_text = cipher_text_with_tag[:-16]
    tag = cipher_text_with_tag[-16:]

    nonce = bytes(4) + p64(counter, endianness='little')
    aead = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    aead.update(auth_text)
    plain_text = aead.decrypt_and_verify(ciphertext=cipher_text, received_mac_tag=tag)
    return plain_text


def wg_xaead_decrypt(key: bytes, nonce: bytes, cipher_text_with_tag: bytes, auth_text: bytes) -> bytes:
    cipher_text = cipher_text_with_tag[:-16]
    tag = cipher_text_with_tag[-16:]

    aead = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    aead.update(auth_text)
    plain_text = aead.decrypt_and_verify(ciphertext=cipher_text, received_mac_tag=tag)
    return plain_text


def wg_hash(data: bytes) -> bytes:
    return hashlib.blake2s(data, digest_size=32).digest()


def wg_mac(key: bytes, data: bytes) -> bytes:
    return hashlib.blake2s(data, key=key, digest_size=16).digest()


def wg_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key=key, msg=data, digestmod=hashlib.blake2s).digest()


def wg_kdf(key: bytes, data: bytes, n: int):
    ts = []
    prk = hmac.new(key=key, msg=data, digestmod=hashlib.blake2s).digest()
    prk_hash = hmac.new(prk, digestmod=hashlib.blake2s)
    t = b''
    for i in range(1, n + 1):
        prk_hash_i = prk_hash.copy()
        prk_hash_i.update(t + i.to_bytes(1, 'big'))
        t = prk_hash_i.digest()
        ts.append(t)
    return ts[0] if n == 1 else tuple(ts)


def wg_timestamp() -> bytes:
    now = time.time()
    seconds = int(now)
    nanoseconds = int((now - seconds) * 1_000_000_000)
    tai_bytes = p64(seconds, endianness='big') + p32(nanoseconds, endianness='big')
    return tai_bytes


def wg_construction() -> bytes:
    return "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".encode("UTF-8")


def wg_identifier() -> bytes:
    return "WireGuard v1 zx2c4 Jason@zx2c4.com".encode("UTF-8")


def wg_label_mac1() -> bytes:
    return "mac1----".encode("UTF-8")


def wg_label_cookie() -> bytes:
    return "cookie--".encode("UTF-8")


def get_public_key_from_private_key(private_key: bytes) -> bytes:
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_key)
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return public_bytes
