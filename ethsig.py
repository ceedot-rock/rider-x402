#!/usr/bin/env python3
"""ethsig: minimal pure-stdlib Ethereum signature tools for rider-x402.

Provides keccak256 and EIP-191 personal_sign verification (ecrecover) so
the x402 server can bind a txHash payment proof to the paying address
without any third-party dependency. Lives on the persistent volume next
to server.py.

Only what we need is implemented: no signing, no key generation.
"""

# --------------------------------------------------------------------------
# keccak256 (Ethereum's Keccak, NOT NIST SHA3: pad byte 0x01, no 0x06 domain)
# --------------------------------------------------------------------------

_KECCAK_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_MASK64 = (1 << 64) - 1


def _keccak_f1600(state):
    for rnd in range(24):
        # theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ ((c[(x + 1) % 5] << 1) & _MASK64
                                | c[(x + 1) % 5] >> 63) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # rho + pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = (
                    ((state[x + 5 * y] << _KECCAK_ROT[x][y]) & _MASK64)
                    | (state[x + 5 * y] >> (64 - _KECCAK_ROT[x][y]))
                ) if _KECCAK_ROT[x][y] else state[x + 5 * y]
        # chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y] & _MASK64)
                                                   & b[(x + 2) % 5 + 5 * y])
        # iota
        state[0] ^= _KECCAK_RC[rnd]


def keccak256(data: bytes) -> bytes:
    """Ethereum keccak256."""
    # rate = 1088 bits = 136 bytes for 256-bit output
    state = [0] * 25
    off = 0
    data = bytearray(data)
    while off < len(data):
        block = data[off:off + 136]
        if len(block) == 136:
            for i in range(17):
                word = int.from_bytes(block[8 * i:8 * i + 8], "little")
                state[i] ^= word
            _keccak_f1600(state)
            off += 136
        else:
            break
    # pad10*1 with domain 0x01
    tail = bytearray(data[off:off + 136])
    tail.append(0x01)
    while len(tail) < 136:
        tail.append(0x00)
    tail[-1] |= 0x80
    for i in range(17):
        word = int.from_bytes(tail[8 * i:8 * i + 8], "little")
        state[i] ^= word
    _keccak_f1600(state)
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))


# --------------------------------------------------------------------------
# secp256k1 ECDSA public-key recovery (ecrecover)
# --------------------------------------------------------------------------

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _inv(a):
    return pow(a, _P - 2, _P)


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None
        lam = (3 * x1 * x1) * _inv((2 * y1) % _P) % _P  # doubling
    else:
        lam = ((y2 - y1) % _P) * _inv((x2 - x1) % _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return (x3, (lam * (x1 - x3) - y1) % _P)


def _point_mul(k, point=(_GX, _GY)):
    res = None
    add = point
    while k:
        if k & 1:
            res = _point_add(res, add)
        add = _point_add(add, add)
        k >>= 1
    return res


def _decompress(x, odd):
    y2 = (pow(x, 3, _P) + 7) % _P
    y = pow(y2, (_P + 1) // 4, _P)
    if (y * y) % _P != y2:
        return None
    if (y & 1) != odd:
        y = _P - y
    return (x, y)


def ecrecover(msg_hash: bytes, v: int, r: int, s: int):
    """Recover the (x, y) public key point from a 65-byte-style signature.

    v is 27/28 (or 0/1). Returns None if the signature is invalid.
    """
    if len(msg_hash) != 32 or not (1 <= r < _N) or not (1 <= s < _N):
        return None
    recid = v - 27 if v >= 27 else v
    if recid not in (0, 1):
        return None
    e = int.from_bytes(msg_hash, "big") % _N
    x = r + (recid // 2) * _N
    if x >= _P:
        return None
    r_pt = _decompress(x, recid % 2)
    if r_pt is None:
        return None
    r_inv = pow(r, _N - 2, _N)
    u1 = (_N - e * r_inv) % _N
    u2 = (s * r_inv) % _N
    q = _point_add(_point_mul(u1), _point_mul(u2, r_pt))
    if q is None:
        return None
    # sanity: recovered key must verify (guards edge cases)
    return q


def pubkey_to_address(point) -> bytes:
    x, y = point
    return keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[12:]


# --------------------------------------------------------------------------
# EIP-191 personal_sign verification
# --------------------------------------------------------------------------

def eth_personal_message(message: bytes) -> bytes:
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(message)).encode()
    return keccak256(prefix + message)


def verify_personal_sign(message: bytes, sig_hex: str):
    """Verify an EIP-191 personal_sign signature.

    Returns the 20-byte signer address on success, None on failure.
    sig_hex: 0x-prefixed 65-byte hex (r || s || v), v in {27, 28} or {0, 1}.
    """
    try:
        s = sig_hex.strip()
        if s.startswith(("0x", "0X")):
            s = s[2:]
        raw = bytes.fromhex(s)
        if len(raw) != 65:
            return None
        r = int.from_bytes(raw[0:32], "big")
        ss = int.from_bytes(raw[32:64], "big")
        v = raw[64]
        # malleability guard: s must be low (as wallets produce)
        if ss > _N // 2:
            return None
        digest = eth_personal_message(message)
        q = ecrecover(digest, v, r, ss)
        if q is None:
            return None
        return pubkey_to_address(q)
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------
# secp256k1 ECDSA signing (RFC 6979 deterministic k)
# --------------------------------------------------------------------------

import hashlib as _hashlib
import hmac as _hmac


def _rfc6979(priv: int, h1: bytes) -> int:
    """Deterministic nonce per RFC 6979 (HMAC-SHA256)."""
    x = priv.to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = _hmac.new(k, v + b"\x00" + x + h1, _hashlib.sha256).digest()
    v = _hmac.new(k, v, _hashlib.sha256).digest()
    k = _hmac.new(k, v + b"\x01" + x + h1, _hashlib.sha256).digest()
    v = _hmac.new(k, v, _hashlib.sha256).digest()
    while True:
        v = _hmac.new(k, v, _hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < _N:
            return cand
        k = _hmac.new(k, v + b"\x00", _hashlib.sha256).digest()
        v = _hmac.new(k, v, _hashlib.sha256).digest()


def privkey_to_address(privkey_hex: str) -> bytes:
    """20-byte address for a 0x-prefixed (or bare) 32-byte hex private key."""
    s = privkey_hex.strip()
    if s[:2] in ("0x", "0X"):
        s = s[2:]
    priv = int(s, 16)
    if not (1 <= priv < _N):
        raise ValueError("private key out of range")
    return pubkey_to_address(_point_mul(priv))


def sign_personal(message: bytes, privkey_hex: str) -> str:
    """EIP-191 personal_sign with a local private key.

    Returns 0x-prefixed 65-byte hex (r || s || v), v in {27, 28}, low-s.
    Deterministic (RFC 6979). Round-trips through verify_personal_sign.
    """
    s = privkey_hex.strip()
    if s[:2] in ("0x", "0X"):
        s = s[2:]
    priv = int(s, 16)
    if not (1 <= priv < _N):
        raise ValueError("private key out of range")
    digest = eth_personal_message(message)
    e = int.from_bytes(digest, "big") % _N
    pub = _point_mul(priv)
    ctr = 0
    while True:
        # domain-separate retries (practically never taken) via HMAC key tweak
        k_input = digest if ctr == 0 else keccak256(digest + ctr.to_bytes(4, "big"))
        k = _rfc6979(priv, k_input)
        r_pt = _point_mul(k)
        r = r_pt[0] % _N
        if r == 0:
            ctr += 1
            continue
        s_val = (pow(k, _N - 2, _N) * (e + r * priv)) % _N
        if s_val == 0:
            ctr += 1
            continue
        if s_val > _N // 2:
            s_val = _N - s_val
        for v in (27, 28):
            if ecrecover(digest, v, r, s_val) == pub:
                return ("0x" + r.to_bytes(32, "big").hex()
                        + s_val.to_bytes(32, "big").hex() + bytes([v]).hex())
        ctr += 1


# --------------------------------------------------------------------------
# rider-x402 binding message
# --------------------------------------------------------------------------

def binding_message(tx_hash: str, resource: str) -> bytes:
    """Canonical message the payer signs to bind a txHash proof to their
    address and to the exact endpoint being called."""
    return ("rider-x402 payment proof\n"
            "txHash: %s\n"
            "resource: %s" % (tx_hash.strip().lower(), resource.strip())).encode()
