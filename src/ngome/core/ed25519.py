"""What every Ed25519 public key we take must pass, whoever checks signatures with it."""

KEY_BYTES = 32

# The eight points of small order on the curve, as every encoding a lenient verifier takes
# for them: the five y values, the two of those that can also be written with the field size
# added, and (masked off before the lookup) either sign bit.
_SMALL_ORDER = frozenset(
    bytes.fromhex(encoding)
    for encoding in (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    )
)


def is_small_order(raw: bytes) -> bool:
    """Whether 32 bytes encode an Ed25519 point of small order.

    Such a "public key" has no private half and needs none: with the identity as the key,
    the identity and zero are a valid signature over any message. No real key is one.
    """
    return len(raw) == KEY_BYTES and raw[:31] + bytes([raw[31] & 0x7F]) in _SMALL_ORDER
