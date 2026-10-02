"""Bitcoin rail helpers for rider-x402.

Pure-stdlib Bitcoin primitives (no new dependencies): bech32/base58check
address handling, Bitcoin signed-message sign/verify (secp256k1 recovery
reuses ethsig's pure-python curve code), mempool.space price + tx lookup,
and cents-to-satoshis pricing.

The rail lets payers settle native BTC on Bitcoin mainnet. Verification
shape mirrors the EVM/Solana rails: the tx must be confirmed, must pay at
least the priced satoshis to PAY_TO_BTC, and the payer must bind the proof
with a Bitcoin signed message over ethsig.binding_message(txid, resource)
whose recovered address is one of the funding inputs (front-running
protection, same role as payerSig on EVM).
"""

import base64
import binascii
import hashlib
import json
import time
import urllib.request

import ethsig

# --------------------------------------------------------------------------
# hashing
# --------------------------------------------------------------------------

def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _ripemd160_fallback(data: bytes) -> bytes:
    """Pure-python RIPEMD-160 (only used when hashlib lacks it)."""
    # Initial values
    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    # Message schedule orderings per round
    R1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    R2 = [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8]
    R3 = [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12]
    R4 = [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2]
    R5 = [9, 15, 5, 11, 6, 8, 13, 12, 2, 10, 0, 4, 3, 7, 1, 14]
    RL = [R1, R2, R3, R4, R5]
    RR = [R5, R4, R3, R2, R1]
    SL = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8]
    SR = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6]
    KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]

    def _f(j, x, y, z):
        if j < 16:
            return x ^ y ^ z
        if j < 32:
            return (x & y) | (~x & z)
        if j < 48:
            return (x | ~y) ^ z
        if j < 64:
            return (x & z) | (y & ~z)
        return x ^ (y | ~z)

    def _rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    msg = bytearray(data)
    ml = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += ml.to_bytes(8, "little")
    for off in range(0, len(msg), 64):
        X = [int.from_bytes(msg[off + 4 * i:off + 4 * i + 4], "little")
             for i in range(16)]
        al, bl, cl, dl, el = h0, h1, h2, h3, h4
        ar, br, cr, dr, er = h0, h1, h2, h3, h4
        for j in range(80):
            rnd = j // 16
            # left line
            t = (al + _f(j, bl, cl, dl) + X[RL[rnd][j % 16]] + KL[rnd]) & 0xFFFFFFFF
            t = (_rol(t, SL[j]) + el) & 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, _rol(cl, 10), bl, t
            # right line
            t = (ar + _f(79 - j, br, cr, dr) + X[RR[rnd][j % 16]] + KR[rnd]) & 0xFFFFFFFF
            t = (_rol(t, SR[j]) + er) & 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, _rol(cr, 10), br, t
        t = (h1 + cl + dr) & 0xFFFFFFFF
        h1 = (h2 + dl + er) & 0xFFFFFFFF
        h2 = (h3 + el + ar) & 0xFFFFFFFF
        h3 = (h4 + bl + br) & 0xFFFFFFFF
        h4 = (h0 + cl + cr) & 0xFFFFFFFF
        h0 = t
    return b"".join(h.to_bytes(4, "little") for h in (h0, h1, h2, h3, h4))


def hash160(b: bytes) -> bytes:
    sha = hashlib.sha256(b).digest()
    try:
        return hashlib.new("ripemd160", sha).digest()
    except Exception:
        return _ripemd160_fallback(sha)


# --------------------------------------------------------------------------
# bech32 (BIP-173)
# --------------------------------------------------------------------------

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD,
                    0x2A1462B3][i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_verify_checksum(hrp, data):
    return _bech32_polymod(_bech32_hrp_expand(hrp) + data) == 1


def _bech32_create_checksum(hrp, data):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    data = [witver] + _convertbits(witprog, 8, 5)
    combined = data + _bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in combined)


def bech32_decode(addr: str):
    """Returns (hrp, witver, witprog_bytes) or None."""
    try:
        if addr.lower() != addr and addr.upper() != addr:
            return None
        addr = addr.lower()
        pos = addr.rfind("1")
        if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
            return None
        hrp = addr[:pos]
        data = [_BECH32_CHARSET.find(c) for c in addr[pos + 1:]]
        if any(d == -1 for d in data):
            return None
        if not _bech32_verify_checksum(hrp, data):
            return None
        witver = data[0]
        prog = _convertbits(data[1:-6], 5, 8, False)
        if prog is None or not (2 <= len(prog) <= 40):
            return None
        if witver == 0 and len(prog) not in (20, 32):
            return None
        return hrp, witver, bytes(prog)
    except Exception:
        return None


# --------------------------------------------------------------------------
# base58check
# --------------------------------------------------------------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check_encode(payload: bytes) -> str:
    n = int.from_bytes(payload + sha256d(payload)[:4], "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = _B58_ALPHABET[r] + s
    pad = 0
    for c in payload:
        if c == 0:
            pad += 1
        else:
            break
    return "1" * pad + s


def b58check_decode(s: str):
    """Returns payload bytes (without checksum) or None."""
    try:
        n = 0
        for c in s:
            n = n * 58 + _B58_ALPHABET.index(c)
        full = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
        pad = 0
        for c in s:
            if c == "1":
                pad += 1
            else:
                break
        full = b"\x00" * pad + full
        if len(full) < 5:
            return None
        payload, checksum = full[:-4], full[-4:]
        if sha256d(payload)[:4] != checksum:
            return None
        return payload
    except Exception:
        return None


# --------------------------------------------------------------------------
# address helpers
# --------------------------------------------------------------------------

def is_valid_btc_address(addr: str) -> bool:
    """Accept P2WPKH (bc1q), P2PKH (1...), P2SH (3...) mainnet addresses."""
    a = (addr or "").strip()
    if a.startswith("bc1q") or a.startswith("bc1Q"):
        dec = bech32_decode(a)
        return dec is not None and dec[0] == "bc" and dec[1] == 0 and len(dec[2]) == 20
    if a.startswith("1"):
        p = b58check_decode(a)
        return p is not None and len(p) == 21 and p[0] == 0x00
    if a.startswith("3"):
        p = b58check_decode(a)
        return p is not None and len(p) == 21 and p[0] == 0x05
    return False


def _compressed_pubkey(point) -> bytes:
    x, y = point
    return (b"\x02" if y % 2 == 0 else b"\x03") + x.to_bytes(32, "big")


def point_to_p2wpkh(point) -> str:
    return bech32_encode("bc", 0, hash160(_compressed_pubkey(point)))


def point_to_p2pkh(point, compressed: bool = True) -> str:
    x, y = point
    if compressed:
        pub = _compressed_pubkey(point)
    else:
        pub = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    return b58check_encode(b"\x00" + hash160(pub))


# --------------------------------------------------------------------------
# Bitcoin signed messages ("Bitcoin Signed Message:\n" format)
# --------------------------------------------------------------------------

def btc_message_hash(message: bytes) -> bytes:
    def _varint(n):
        if n < 0xFD:
            return bytes([n])
        if n <= 0xFFFF:
            return b"\xfd" + n.to_bytes(2, "little")
        return b"\xfe" + n.to_bytes(4, "little")
    return sha256d(b"\x18Bitcoin Signed Message:\n" + _varint(len(message)) + message)


def sign_btc_message(message: bytes, privkey: bytes) -> str:
    """Sign with a 32-byte private key. Returns base64 signature.

    For local testing / the lab's own smoke payer only.
    """
    priv = int.from_bytes(privkey, "big")
    if not (1 <= priv < ethsig._N):
        raise ValueError("private key out of range")
    digest = btc_message_hash(message)
    e = int.from_bytes(digest, "big") % ethsig._N
    pub = ethsig._point_mul(priv)
    k = ethsig._rfc6979(priv, digest)
    r = ethsig._point_mul(k)[0] % ethsig._N
    s_val = (pow(k, ethsig._N - 2, ethsig._N) * (e + r * priv)) % ethsig._N
    if s_val > ethsig._N // 2:
        s_val = ethsig._N - s_val
    # find recid that recovers our pubkey (compressed)
    for recid in (0, 1):
        q = ethsig.ecrecover(digest, 27 + recid, r, s_val)
        if q is not None and _compressed_pubkey(q) == _compressed_pubkey(pub):
            header = 27 + recid + 4
            raw = bytes([header]) + r.to_bytes(32, "big") + s_val.to_bytes(32, "big")
            return base64.b64encode(raw).decode("ascii")
    raise RuntimeError("recovery id not found")


def verify_btc_message(message: bytes, sig_b64: str, address: str) -> bool:
    """Verify a Bitcoin signed message against an address.

    Supports P2WPKH (bc1q) and P2PKH (1...) senders. Returns True/False.
    """
    try:
        raw = base64.b64decode(sig_b64.strip(), validate=True)
        if len(raw) != 65:
            return False
        header = raw[0]
        if not (27 <= header <= 34):
            return False
        recid = (header - 27) & 3
        compressed = bool((header - 27) & 4)
        r = int.from_bytes(raw[1:33], "big")
        s_val = int.from_bytes(raw[33:65], "big")
        digest = btc_message_hash(message)
        q = ethsig.ecrecover(digest, 27 + recid, r, s_val)
        if q is None:
            return False
        a = (address or "").strip()
        if a.lower().startswith("bc1q"):
            if not compressed:
                return False
            return point_to_p2wpkh(q).lower() == a.lower()
        if a.startswith("1"):
            cand_c = point_to_p2pkh(q, True)
            cand_u = point_to_p2pkh(q, False)
            return a == cand_c or (not compressed and a == cand_u)
        return False
    except (binascii.Error, ValueError, TypeError):
        return False


# --------------------------------------------------------------------------
# mempool.space / blockstream API
# --------------------------------------------------------------------------

_BTC_APIS = ["https://mempool.space/api", "https://blockstream.info/api"]
_UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}


def _btc_get(path: str, timeout: int = 25):
    last = None
    for base in _BTC_APIS:
        try:
            req = urllib.request.Request(base + path, headers=_UA)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)
        except Exception as e:  # noqa: BLE001 - try next API
            last = str(e)[:100]
    raise RuntimeError("bitcoin API unreachable: %s" % (last or "unknown"))


def _btc_get_text(path: str, timeout: int = 25) -> str:
    """Plain-text endpoints (e.g. /blocks/tip/height)."""
    last = None
    for base in _BTC_APIS:
        try:
            req = urllib.request.Request(base + path, headers=_UA)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace").strip()
        except Exception as e:  # noqa: BLE001 - try next API
            last = str(e)[:100]
    raise RuntimeError("bitcoin API unreachable: %s" % (last or "unknown"))


_price_cache = {"t": 0.0, "usd": 0.0}
_PRICE_TTL = 120.0


def btc_usd_price() -> float:
    """Current BTC/USD from mempool.space (cached 120s). Raises on failure."""
    now = time.time()
    if _price_cache["usd"] > 0 and now - _price_cache["t"] < _PRICE_TTL:
        return _price_cache["usd"]
    data = _btc_get("/v1/prices")
    usd = float(data.get("USD") or 0)
    if usd <= 0:
        raise RuntimeError("bad BTC price from API")
    _price_cache.update(t=now, usd=usd)
    return usd


def sats_for_cents(cents: int, price_usd: float = None) -> int:
    """Satoshis for a US-cent price, rounded UP (payer never underpays)."""
    usd = price_usd if price_usd else btc_usd_price()
    if usd <= 0:
        raise RuntimeError("no BTC price")
    import math
    return max(1, math.ceil(cents * 1e8 / (100.0 * usd)))


def fetch_btc_tx(txid: str):
    """Full tx object from mempool.space (has vout scriptpubkey_address)."""
    txid = (txid or "").strip().lower()
    if len(txid) != 64 or any(c not in "0123456789abcdef" for c in txid):
        raise ValueError("bad txid")
    return _btc_get("/tx/%s" % txid)


def fetch_btc_tx_outspends(txid: str):
    """Per-output spend status (detects double-spend attempts)."""
    return _btc_get("/tx/%s/outspends" % txid.strip().lower())
