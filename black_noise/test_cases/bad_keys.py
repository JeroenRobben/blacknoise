# Known-bad X25519 public keys used across ephemeral and static key verification tests.

# The X25519 identity point; DH always returns all-zeros output.
ALL_ZEROS = bytes(32)

# Low-order point of order 4 on Curve25519.
LOW_ORDER_POINT = bytes.fromhex(
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
)

# All bad public keys paired with a short description for use in test error messages.
BAD_PUBLIC_KEYS: list[tuple[bytes, str]] = [
    (ALL_ZEROS,       "all-zeros"),
    (LOW_ORDER_POINT, "low-order point (order 4)"),
]
