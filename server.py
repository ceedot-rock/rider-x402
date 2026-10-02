#!/usr/bin/env python3
"""rider-x402: HTTP 402 endpoint for Agent Rider products (Slid Phi Labs).

Unpaid callers get `402 Payment Required` with an x402 v2-style
PaymentRequirements JSON body (<300ms, no chain IO) plus a
`PAYMENT-REQUIRED` header carrying base64url(PaymentRequirements) for
standard x402 clients.

Paid callers retry with:
    X-PAYMENT: base64url(JSON({
        "x402Version": 2,
        "scheme": "txHash",
        "network": "eip155:8453",
        "payload": {
            "txHash": "0x...",      # native USDC transfer to payTo
            "payerSig": "0x..."     # EIP-191 personal_sign by the paying
                                    # address over the binding message in
                                    # extra.howto (front-running protection)
        }
    }))
proving a Base USDC transfer to the lab wallet. The tx is verified
on-chain (format, replay, receipt exists + ok, real USDC Transfer events
paying the lab address >= price) and each txhash is accepted once.
NOTE: this endpoint uses txhash proof rather than an EIP-3009 meta-tx,
so the payer pays their own gas and we settle nothing. The scheme is
deliberately NOT called "exact": in x402 that name means an EIP-3009
signed authorization, and advertising it makes standard clients sign,
get re-challenged and loop. Older integrators sending "exact" are still
accepted (backward compat).

Products are the lab's own binaries (pccx, slidx, cuni) run in
subprocesses with byte caps and timeouts, mirroring the Rider DM daemon.

Env:
    X402_PAY_TO     lab wallet receiving USDC (0x...) — same address works
                    on every EVM rail
    X402_PAY_TO_SOL lab wallet receiving SPL USDC on Solana (base58 address);
                    unset disables the Solana rail
    X402_RPC_URLS   comma-separated Base JSON-RPC URLs (required)
    POLYGON_RPC_URL / ARBITRUM_RPC_URL / OPTIMISM_RPC_URL
                    comma-separated JSON-RPC URLs per chain; fall back to
                    public endpoints when unset. Free-tier providers with
                    keys: Alchemy, Infura.
    SOLANA_RPC_URL  comma-separated Solana JSON-RPC URLs; falls back to a
                    public endpoint when unset. Free-tier with key:
                    Helius, Alchemy.
    PORT            listen port (default 8080)
    SRV_DIR         persistent dir (default /srv)

Rails accepted (mainnet only, no testnets):
    Base eip155:8453, Polygon eip155:137, Arbitrum One eip155:42161,
    Optimism eip155:10 — native USDC (6 decimals) on each, verified with
    the exact same receipt + Transfer-log summation as before.
    Solana solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp — SPL USDC, verified via
    getTransaction (jsonParsed) balance deltas.
"""
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import awareness as awareness_mod
import trustream as trustream_mod
import ethsig
import refund as refund_mod
import btcrail as btc_mod

# Canonical native USDC on Base mainnet (6 decimals), verified against
# Circle's official docs 2026-09-24. Do not change without Corey's say-so.
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
TRANSFER_TOPIC = ("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a"
                  "4df523b3ef")
USDC_DECIMALS = 6
UNITS_PER_CENT = 10 ** (USDC_DECIMALS - 2)

NETWORK_CAIP2 = "eip155:8453"
X402_VERSION = 2
# Scheme name for our txHash/signature proof flow. NOT "exact": in x402
# "exact" means an EIP-3009 signed authorization to standard clients, and
# advertising it while expecting a txHash makes them sign, get re-challenged
# and loop forever. "txHash" is honest about what we actually verify.
# The parser still accepts "exact" from older integrators (backward compat).
PAY_SCHEME = "txHash"

# --------------------------------------------------------------------------
# multi-rail config
# EVM rails reuse the exact Base verify shape: receipt + USDC Transfer-log
# summation to PAY_TO + underpaid check. Native USDC ONLY on every chain —
# bridged USDC.e lives at different addresses and is never accepted.
# Contracts verified against Circle's official docs 2026-09-25.
# --------------------------------------------------------------------------
EVM_RAILS = {
    "eip155:8453": {
        "label": "Base",
        "rpc_env": "X402_RPC_URLS",
        "fallback": [],
        "usdc": USDC_BASE,
    },
    "eip155:137": {
        "label": "Polygon",
        "rpc_env": "POLYGON_RPC_URL",
        "fallback": ["https://1rpc.io/matic",
                     "https://rpc.ankr.com/polygon"],
        "usdc": "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
    },
    "eip155:42161": {
        "label": "Arbitrum One",
        "rpc_env": "ARBITRUM_RPC_URL",
        "fallback": ["https://arb1.arbitrum.io/rpc"],
        "usdc": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
    },
    "eip155:10": {
        "label": "Optimism",
        "rpc_env": "OPTIMISM_RPC_URL",
        "fallback": ["https://1rpc.io/op",
                     "https://rpc.ankr.com/optimism"],
        "usdc": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
    },
}

SOLANA_NETWORK = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
SOL_USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # 6 decimals
SOL_SIG_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{87,88}$")

# Bitcoin rail: native BTC on mainnet. CAIP-2 uses the genesis block hash;
# the asset follows CAIP-19 (slip44:0 = native BTC).
BITCOIN_NETWORK = "bip122:000000000019d6689c085ae165831e934"
BITCOIN_ASSET = "bip122:000000000019d6689c085ae165831e934/slip44:0"
BTC_TXID_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _rail_rpcs(rail):
    urls = [u.strip() for u in os.environ.get(rail["rpc_env"], "").split(",")
            if u.strip()]
    return urls or rail["fallback"]


def _rail_info():
    """Rails advertised in 402s and info endpoints."""
    info = [{"network": net, "label": rail["label"], "asset": rail["usdc"],
             "payTo": PAY_TO, "kind": "evm"}
            for net, rail in EVM_RAILS.items()]
    if PAY_TO_SOL:
        info.append({"network": SOLANA_NETWORK, "label": "Solana",
                     "asset": SOL_USDC_MINT, "payTo": PAY_TO_SOL,
                     "kind": "solana"})
    if PAY_TO_BTC:
        info.append({"network": BITCOIN_NETWORK, "label": "Bitcoin",
                     "asset": BITCOIN_ASSET, "payTo": PAY_TO_BTC,
                     "kind": "bitcoin"})
    return info

SRV_DIR = os.environ.get("SRV_DIR", "/srv")
PORT = int(os.environ.get("PORT", "8080"))
PAY_TO = os.environ.get("X402_PAY_TO", "").strip()
PAY_TO_SOL = os.environ.get("X402_PAY_TO_SOL", "").strip()
PAY_TO_BTC = os.environ.get("X402_PAY_TO_BTC", "").strip()
RPC_URLS = [u.strip() for u in os.environ.get("X402_RPC_URLS", "").split(",")
            if u.strip()]
SOLANA_RPC_URLS = [u.strip()
                   for u in os.environ.get("SOLANA_RPC_URL", "").split(",")
                   if u.strip()] or ["https://solana-rpc.publicnode.com"]

BIN = {
    "pccx": os.path.join(SRV_DIR, "bin", "pccx"),
    "slidx": os.path.join(SRV_DIR, "bin", "slidx"),
    "cuni": os.path.join(SRV_DIR, "bin", "cuni"),
}
STATE_PATH = os.path.join(SRV_DIR, "state.json")
LOG_PATH = os.path.join(SRV_DIR, "calls.log")

MAX_IN = 8 * 1024 * 1024
MAX_OUT = 16 * 1024 * 1024
CMD_TIMEOUT = 120

# product -> op -> price in US cents
PRODUCTS = {
    "ping": {"ping": 1},
    "pcc": {"compress": 25, "decompress": 10, "info": 2},
    "slidx": {"compress": 25, "decompress": 10, "info": 2},
    "cuni": {"check": 10, "seats": 2, "emit": 25, "ingest": 25},
    "trustream": {"pack": 10, "unpack": 10, "info": 2},
    "awareness": {"scan": 10},
}
DATA_OPS = {("pcc", "compress"), ("pcc", "decompress"),
            ("slidx", "compress"), ("slidx", "decompress"),
            ("cuni", "check"), ("cuni", "emit"), ("cuni", "ingest"),
            ("trustream", "pack"), ("trustream", "unpack")}

# Native CuNi seats and the host toolchain each needs. The check gate runs
# every seat whose toolchain is present (py always: this server is python).
_NATIVE_SEAT_TOOLS = (("py", "python3"), ("go", "go"), ("js", "node"),
                      ("ts", "node"), ("c", "gcc"), ("cpp", "g++"),
                      ("rs", "rustc"))
_CHECK_SEATS = ["py"] + [s for s, b in _NATIVE_SEAT_TOOLS[1:]
                         if shutil.which(b)]

# Per-op query params documented in OpenAPI (also enforced in run_product).
QUERY_PARAMS = {
    ("cuni", "emit"): [{"name": "target", "in": "query", "required": True,
                        "schema": {"type": "string"},
                        "description": "CuNi seat id to emit, e.g. ?target=rs "
                                       "(see cuni/seats for the catalog)"}],
    ("cuni", "ingest"): [{"name": "from", "in": "query", "required": True,
                          "schema": {"type": "string"},
                          "description": "source seat extension, e.g. ?from=py "
                                         "(py, go, js, ts, c, cpp, rs, awk, "
                                         "pl, sh, sql, wat)"}],
}


class ProductError(Exception):
    pass


class InputError(Exception):
    """Caller-side problem: answered 400, not 500."""
    pass


# --------------------------------------------------------------------------
# state (persistent used-txhash set)
# --------------------------------------------------------------------------
_state_lock = threading.Lock()


def _blank_state():
    return {"used_tx": [], "refund_totals": {}, "refund_idem": {}}


def load_state():
    try:
        with open(STATE_PATH) as f:
            s = json.load(f)
            st = _blank_state()
            st["used_tx"] = s.get("used_tx", [])
            # refund extension state: per-payment refunded totals and
            # idempotency-key -> cached RefundResponse (survives restarts so
            # a reboot can never double-pay)
            rt = s.get("refund_totals", {})
            st["refund_totals"] = rt if isinstance(rt, dict) else {}
            ri = s.get("refund_idem", {})
            st["refund_idem"] = ri if isinstance(ri, dict) else {}
            return st
    except (FileNotFoundError, ValueError):
        return _blank_state()


def save_state(state):
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump({
            "used_tx": sorted(state.get("used_tx", []))[-20000:],
            "refund_totals": state.get("refund_totals", {}),
            "refund_idem": state.get("refund_idem", {}),
        }, f)
    os.replace(tmp, STATE_PATH)


def log_call(entry):
    entry = dict(entry)
    entry["ts"] = int(time.time())
    try:
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------
# payment verification (Base USDC, read-only)
# --------------------------------------------------------------------------
def valid_txhash(h):
    return bool(re.fullmatch(r"0x[0-9a-fA-F]{64}", (h or "").strip()))


def _rpc(url, method, params, timeout=25):
    body = json.dumps({"jsonrpc": "2.0", "id": 1,
                       "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "slid-phi-rider-x402/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _rpc_any(method, params, urls):
    last = None
    for u in urls:
        try:
            return _rpc(u, method, params)
        except Exception as e:  # noqa: BLE001 - try next endpoint
            last = e
    raise last if last else RuntimeError("no rpc urls configured")


def _transfer_senders_to(receipt, pay_to, usdc_contract):
    """Distinct token-sender addresses on USDC Transfer logs paying pay_to.

    The payer is the address that sent the tokens, NOT receipt["from"]:
    with ERC-4337 smart accounts tx.from is the bundler, so receipt.from
    would bind the proof to the wrong address.
    """
    senders = set()
    pay_to_lc = pay_to.lower()
    for log in receipt.get("logs", []) or []:
        if not isinstance(log, dict):
            continue
        if (log.get("address") or "").lower() != usdc_contract.lower():
            continue
        topics = log.get("topics", []) or []
        if len(topics) < 3 or (topics[0] or "").lower() != TRANSFER_TOPIC.lower():
            continue
        to_addr = "0x" + (topics[2] or "")[-40:]
        if to_addr.lower() != pay_to_lc:
            continue
        from_addr = "0x" + (topics[1] or "")[-40:]
        if from_addr.startswith("0x") and len(from_addr) == 42:
            senders.add(from_addr.lower())
    return senders


_ERC1271_SELECTOR = ethsig.keccak256(b"isValidSignature(bytes32,bytes)")[:4]  # 0x1626ba7e
_ERC1271_MAGIC_WORD = "0x1626ba7e" + "00" * 28  # bytes4 magic, ABI-padded
_ERC6492_MAGIC_SUFFIX = bytes.fromhex(
    "6492649264926492649264926492649264926492649264926492649264926492")


def _sig_raw_bytes(payer_sig):
    try:
        s = (payer_sig or "").strip()
        if s[:2] in ("0x", "0X"):
            s = s[2:]
        raw = bytes.fromhex(s)
        return raw or None
    except (ValueError, TypeError, AttributeError):
        return None


def _verify_payer_sig_contract(payer, msg, payer_sig, call):
    """ERC-1271 fallback when ecrecover did not match the token sender.

    Smart-account payers sign with personal_sign too, but the signature is
    an ERC-1271 contract signature, so ecrecover cannot recover it. Ask the
    payer contract itself via isValidSignature. Returns (ok, reason).
    """
    raw = _sig_raw_bytes(payer_sig)
    if raw is None:
        return False, "payerSig invalid: not a valid EIP-191 personal_sign signature"
    try:
        code = ((call("eth_getCode", [payer, "latest"]) or {}).get("result") or "")
    except Exception as e:  # noqa: BLE001 - surfaced as clean failure
        return False, "payerSig check failed: could not read payer code (%s)" % str(e)[:80]
    if code.lower() not in ("", "0x", "0x0"):
        digest = ethsig.eth_personal_message(msg)
        data = ("0x" + _ERC1271_SELECTOR.hex()
                + digest.hex()
                + (64).to_bytes(32, "big").hex()
                + len(raw).to_bytes(32, "big").hex()
                + raw.hex() + "00" * ((-len(raw)) % 32))
        try:
            resp = call("eth_call", [{"to": payer, "data": data}, "latest"]) or {}
        except Exception as e:  # noqa: BLE001 - surfaced as clean failure
            return False, "payerSig check failed: ERC-1271 call failed (%s)" % str(e)[:80]
        if ((resp.get("result") or "").lower()) == _ERC1271_MAGIC_WORD:
            return True, ""
        return False, ("payerSig rejected by the payer smart account: ERC-1271 "
                       "isValidSignature did not return the magic value")
    if raw.endswith(_ERC6492_MAGIC_SUFFIX):
        return False, ("payer is an undeployed smart account (ERC-6492): deploy "
                       "the account first, then pay from it")
    return False, ("payerSig signer does not match the paying (token-sender) "
                   "address %s; sign with the address that sent the USDC" % payer)


def _sum_usdc_to(receipt, pay_to, usdc_contract):
    total = 0
    pay_to_lc = pay_to.lower()
    for log in receipt.get("logs", []) or []:
        if not isinstance(log, dict):
            continue
        if (log.get("address") or "").lower() != usdc_contract.lower():
            continue
        topics = log.get("topics", []) or []
        if len(topics) < 3 or (topics[0] or "").lower() != TRANSFER_TOPIC.lower():
            continue
        to_addr = "0x" + (topics[2] or "")[-40:]
        if to_addr.lower() != pay_to_lc:
            continue
        try:
            total += int(log.get("data", "0x0"), 16)
        except (ValueError, TypeError):
            continue
    return total


def _sum_sol_usdc_to(meta, pay_to):
    """Sum positive SPL-USDC balance deltas to pay_to in a jsonParsed tx."""
    total = 0
    pre = {}
    for b in meta.get("preTokenBalances") or []:
        if isinstance(b, dict) and b.get("accountIndex") is not None:
            pre[b["accountIndex"]] = b
    for b in meta.get("postTokenBalances") or []:
        if not isinstance(b, dict):
            continue
        if b.get("mint") != SOL_USDC_MINT:
            continue
        if (b.get("owner") or "") != pay_to:
            continue
        pre_b = pre.get(b.get("accountIndex"), {})
        try:
            post_amt = int((b.get("uiTokenAmount") or {}).get("amount") or 0)
            pre_amt = int((pre_b.get("uiTokenAmount") or {}).get("amount")
                          or 0)
        except (ValueError, TypeError):
            continue
        if post_amt > pre_amt:
            total += post_amt - pre_amt
    return total


def _verify_evm(tx_hash, network, rail, min_units, used_set, rpc=None,
                payer_sig=None, resource=None):
    """Exact same shape as the original Base check, per-chain config.

    payer_sig binds the proof to the caller: an EIP-191 personal_sign by
    the token sender's address (the USDC Transfer's from, not tx.from --
    with 4337 accounts tx.from is the bundler) over
    ethsig.binding_message(tx_hash, resource). Smart-account payers verify
    via ERC-1271 isValidSignature; undeployed (ERC-6492) accounts are
    refused with a specific reason. Without it anyone watching payTo could
    front-run someone else's txHash.
    """
    h = (tx_hash or "").strip()
    key = "%s:%s" % (network, h.lower())
    if not valid_txhash(h):
        return False, {"reason": "bad txhash format (want 0x + 64 hex)"}
    # namespaced replay key; bare legacy Base keys still honored
    if key in used_set or (network == NETWORK_CAIP2 and h.lower() in used_set):
        return False, {"reason": "replay: txhash already used"}
    urls = _rail_rpcs(rail)
    call = rpc if rpc else (lambda m, p: _rpc_any(m, p, urls))
    try:
        resp = call("eth_getTransactionReceipt", [h])
    except Exception as e:  # noqa: BLE001 - surfaced as clean failure
        return False, {"reason": "rpc unreachable: %s" % str(e)[:120]}
    receipt = resp.get("result") if isinstance(resp, dict) else None
    if not receipt:
        return False, {"reason": "tx not found / not mined yet"}
    if receipt.get("status") not in ("0x1", 1):
        return False, {"reason": "tx reverted (status != ok)"}
    payer = (receipt.get("from") or "").lower()
    # Payer = the token sender from the Transfer logs, NOT receipt["from"].
    # With ERC-4337 smart accounts tx.from is the bundler, so receipt.from
    # would bind the proof to the wrong address.
    senders = _transfer_senders_to(receipt, PAY_TO, rail["usdc"])
    if len(senders) > 1:
        return False, {"reason": "ambiguous payer: %d distinct token senders "
                                 "in one tx; pay from a single address"
                       % len(senders)}
    if not senders:
        return False, {"reason": "no USDC transfer to %s in tx logs" % PAY_TO}
    payer = next(iter(senders))
    if not payer_sig:
        return False, {"reason": "missing payerSig: bind the proof with an "
                                 "EIP-191 personal_sign by the paying address "
                                 "(see extra.howto)"}
    msg = ethsig.binding_message(h, resource or "")
    sig_ok = False
    signer = ethsig.verify_personal_sign(msg, payer_sig)
    if signer is not None and ("0x" + signer.hex()).lower() == payer:
        sig_ok = True  # plain EOA personal_sign
    if not sig_ok:
        # Smart-account payer: ecrecover cannot match an ERC-1271 signature,
        # so ask the payer contract itself (ERC-6492 undeployed accounts get
        # a specific refusal, not a silent accept).
        sig_ok, sig_reason = _verify_payer_sig_contract(payer, msg, payer_sig, call)
    if not sig_ok:
        return False, {"reason": sig_reason}
    paid = _sum_usdc_to(receipt, PAY_TO, rail["usdc"])
    if paid < min_units:
        return False, {"reason": "underpaid: got %.6f USDC, need %.6f"
                                 % (paid / 10 ** USDC_DECIMALS,
                                    min_units / 10 ** USDC_DECIMALS),
                       "paid_units": paid}
    used_set.add(key)
    return True, {"paid_units": paid, "tx": h, "network": network,
                  "payer": payer}


def _sol_get_tx(call, sig):
    """getTransaction, retrying at a higher maxSupportedTransactionVersion
    if the node reports a newer tx version than we asked for."""
    params = {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}
    resp = call("getTransaction", [sig, params])
    if isinstance(resp, dict) and isinstance(resp.get("error"), dict) \
            and "maxSupportedTransactionVersion" in str(
                resp["error"].get("message", "")):
        params = {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 10}
        resp = call("getTransaction", [sig, params])
    return resp


def _verify_solana(sig, min_units, used_set, rpc=None):
    sig = (sig or "").strip()
    key = "sol:" + sig
    if not SOL_SIG_RE.fullmatch(sig):
        return False, {"reason": "bad signature format (want base58, 87-88 chars)"}
    if key in used_set:
        return False, {"reason": "replay: signature already used"}
    call = rpc if rpc else (lambda m, p: _rpc_any(m, p, SOLANA_RPC_URLS))
    try:
        resp = _sol_get_tx(call, sig)
    except Exception as e:  # noqa: BLE001 - surfaced as clean failure
        return False, {"reason": "rpc unreachable: %s" % str(e)[:120]}
    resp = resp if isinstance(resp, dict) else {}
    tx = resp.get("result")
    if not tx:
        rpc_err = resp.get("error") or {}
        msg = rpc_err.get("message") if isinstance(rpc_err, dict) else None
        if msg:
            return False, {"reason": "rpc error: %s" % str(msg)[:120]}
        return False, {"reason": "tx not found / not finalized yet"}
    meta = tx.get("meta") or {}
    if meta.get("err"):
        return False, {"reason": "tx failed on-chain: %s" % str(meta.get("err"))[:80]}
    paid = _sum_sol_usdc_to(meta, PAY_TO_SOL)
    if paid < min_units:
        return False, {"reason": "underpaid: got %.6f USDC, need %.6f"
                                 % (paid / 10 ** USDC_DECIMALS,
                                    min_units / 10 ** USDC_DECIMALS),
                       "paid_units": paid}
    used_set.add(key)
    return True, {"paid_units": paid, "tx": sig, "network": SOLANA_NETWORK}


def _verify_bitcoin(txid, min_sats, used_set, payer_sig=None, resource=None):
    """Verify a native-BTC payment on Bitcoin mainnet.

    The tx must be confirmed, must pay >= min_sats to PAY_TO_BTC, and
    payer_sig must be a Bitcoin signed message over
    ethsig.binding_message(txid, resource) that recovers to one of the
    funding input addresses (front-running protection, same role as
    payerSig on EVM).
    """
    h = (txid or "").strip().lower()
    key = "btc:" + h
    if not BTC_TXID_RE.fullmatch(h or ""):
        return False, {"reason": "bad txid format (want 64 hex chars)"}
    if key in used_set:
        return False, {"reason": "replay: txid already used"}
    try:
        tx = btc_mod.fetch_btc_tx(h)
    except Exception as e:  # noqa: BLE001 - surfaced as clean failure
        return False, {"reason": "bitcoin API unreachable: %s" % str(e)[:120]}
    status = tx.get("status") or {}
    if not status.get("confirmed"):
        return False, {"reason": "tx not confirmed yet — wait for 1 confirmation"}
    min_confs = int(os.environ.get("X402_BTC_MIN_CONFS", "1") or 1)
    if min_confs > 1:
        try:
            tip = btc_mod._btc_get_text("/blocks/tip/height")
            confs = int(tip) - int(status.get("block_height") or 0) + 1
        except Exception:
            confs = 1
        if confs < min_confs:
            return False, {"reason": "tx has %d confirmation(s), need %d"
                           % (confs, min_confs)}
    paid = 0
    for vout in tx.get("vout") or []:
        if not isinstance(vout, dict):
            continue
        if (vout.get("scriptpubkey_address") or "") == PAY_TO_BTC:
            try:
                paid += int(vout.get("value") or 0)
            except (ValueError, TypeError):
                pass
    if paid < min_sats:
        return False, {"reason": "underpaid: got %d sats, need %d"
                       % (paid, min_sats),
                       "paid_units": paid}
    if not payer_sig:
        return False, {"reason": "missing payerSig: bind the proof with a "
                                 "Bitcoin signed message by a funding input "
                                 "address (see extra.howto)"}
    senders = set()
    for vin in tx.get("vin") or []:
        if not isinstance(vin, dict):
            continue
        a = (vin.get("prevout") or {}).get("scriptpubkey_address")
        if a:
            senders.add(a)
    if not senders:
        return False, {"reason": "could not read funding inputs"}
    msg = ethsig.binding_message(h, resource or "")
    if not any(btc_mod.verify_btc_message(msg, payer_sig, a) for a in senders):
        return False, {"reason": "payerSig does not match any funding input "
                                 "address (P2WPKH/P2PKH only)"}
    used_set.add(key)
    return True, {"paid_units": paid, "tx": h, "network": BITCOIN_NETWORK}


def verify_payment(proof, network, min_units, used_set, rpc=None,
                   payer_sig=None, resource=None):
    """Returns (ok, info). On success the namespaced proof is added to used_set."""
    if network == SOLANA_NETWORK:
        return _verify_solana(proof, min_units, used_set, rpc)
    if network == BITCOIN_NETWORK:
        # min_units arrives in USDC base units; BTC prices in sats.
        min_sats = btc_mod.sats_for_cents(min_units / UNITS_PER_CENT)
        return _verify_bitcoin(proof, min_sats, used_set, payer_sig, resource)
    rail = EVM_RAILS.get(network)
    if not rail:
        return False, {"reason": "unsupported network %r" % (network,)}
    return _verify_evm(proof, network, rail, min_units, used_set, rpc,
                       payer_sig=payer_sig, resource=resource)


# --------------------------------------------------------------------------
# products
# --------------------------------------------------------------------------
def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _run(argv, timeout=CMD_TIMEOUT):
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ProductError("timed out after %ss: %s" % (timeout, argv[0]))
    except FileNotFoundError:
        raise ProductError("binary not found: %s" % argv[0])
    if p.returncode != 0:
        raise ProductError("%s failed rc=%d: %s" % (
            os.path.basename(argv[0]), p.returncode,
            (p.stderr or p.stdout).decode("utf-8", "replace")[:500]))
    return p


def _check_bin(name):
    path = BIN[name]
    if not (os.path.isfile(path) and os.access(path, os.X_OK)):
        raise ProductError("%s binary missing/not executable: %s" % (name, path))
    return path


def _codec_roundtrip(binary, data, op):
    path = _check_bin(binary)
    tmpd = tempfile.mkdtemp(prefix="x402-")
    try:
        inp = os.path.join(tmpd, "in.bin")
        outp = os.path.join(tmpd, "out.bin")
        with open(inp, "wb") as f:
            f.write(data)
        _run([path, op, inp, outp])
        with open(outp, "rb") as f:
            out = f.read()
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)
    if len(out) > MAX_OUT:
        raise ProductError("output %d bytes exceeds cap %d" % (len(out), MAX_OUT))
    return {"in_bytes": len(data), "out_bytes": len(out),
            "sha256_in": _sha(data), "sha256_out": _sha(out),
            "payload_b64": base64.b64encode(out).decode("ascii")}


_CUNI_LANGS = None


def _cuni_langs():
    """id -> {name, ext} for the 144-seat catalog (cached; restart on upgrade)."""
    global _CUNI_LANGS
    if _CUNI_LANGS is None:
        path = _check_bin("cuni")
        p = _run([path, "--list-langs"], timeout=15)
        langs = {}
        for line in p.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and parts[0].strip():
                langs[parts[0].strip()] = {"name": parts[1].strip(),
                                           "ext": parts[2].strip().lstrip(".")}
        if not langs:
            raise ProductError("cuni --list-langs returned no seats")
        _CUNI_LANGS = langs
    return _CUNI_LANGS


def run_product(product, op, data, params):
    if (product, op) in DATA_OPS:
        if data is None:
            raise ProductError("this op needs a JSON body {\"data\": \"<base64>\"}")
        if len(data) > MAX_IN:
            raise ProductError("input %d bytes exceeds cap %d" % (len(data), MAX_IN))
    if product == "ping":
        return {"pong": True, "ts": int(time.time())}
    if product == "awareness" and op == "scan":
        # data = base64(JSON({"readings": [...], "baseline_temp": f}))
        result, err = awareness_mod.scan(data)
        if err:
            raise ProductError(err)
        result["note"] = ("UberAware attention pass: GNW ignition over "
                          "submitted sensor readings")
        return result
    if product == "pcc" and op == "info":
        _check_bin("pccx")
        return {"binary": "pccx", "version": "pccx-0.3.0",
                "usage": "pccx encode|decode IN OUT",
                "note": "exact-select codec; decode+SHA-256 verified on every call"}
    if product == "slidx" and op == "info":
        _check_bin("slidx")
        return {"binary": "slidx", "note": "match-finder front end + range coder"}
    if product == "cuni" and op == "seats":
        langs = _cuni_langs()
        ids = sorted(langs)
        return {"seat_count": len(ids), "sample": ids[:12],
                "note": "remaining seats run via Python lowering"}
    if product == "cuni" and op == "check":
        path = _check_bin("cuni")
        tmpd = tempfile.mkdtemp(prefix="x402-")
        try:
            src = os.path.join(tmpd, "prog.cuni")
            with open(src, "wb") as f:
                f.write(data)
            p = _run([path, "check", src,
                      "--only", ",".join(_CHECK_SEATS),
                      "--receipt", "--timeout", "10"],
                     timeout=120)
        finally:
            shutil.rmtree(tmpd, ignore_errors=True)
        text = p.stdout.decode("utf-8", "replace")
        m = re.search(r"exactness: PASS \((\d+) langs", text)
        return {"in_bytes": len(data), "sha256_in": _sha(data),
                "seats_run": _CHECK_SEATS, "seat_count": len(_CHECK_SEATS),
                "exactness_pass": "exactness: PASS" in text,
                "gated_langs": int(m.group(1)) if m else 0,
                "harness_tail": "\n".join(text.splitlines()[-8:])}
    if product == "cuni" and op == "emit":
        target = (params.get("target") or "").strip()
        langs = _cuni_langs()
        if target not in langs:
            raise InputError("unknown target seat '%s'; see cuni/seats "
                             "for the 144-seat catalog" % target[:32])
        ext = langs[target]["ext"] or "txt"
        path = _check_bin("cuni")
        tmpd = tempfile.mkdtemp(prefix="x402-")
        try:
            src = os.path.join(tmpd, "prog.cuni")
            outdir = os.path.join(tmpd, "emit")
            os.mkdir(outdir)
            with open(src, "wb") as f:
                f.write(data)
            try:
                p = subprocess.run([path, src, "--emit-all", outdir],
                                   capture_output=True, timeout=120)
            except subprocess.TimeoutExpired:
                raise ProductError("cuni emit timed out after 120s")
            want = os.path.join(outdir, "%s.%s" % (target, ext))
            if not os.path.isfile(want):
                err = ((p.stderr or p.stdout) or b"").decode(
                    "utf-8", "replace")[:500]
                return {"refused": True, "target": target,
                        "in_bytes": len(data), "sha256_in": _sha(data),
                        "reason": err or "emit refused for %s" % target}
            with open(want, "rb") as f:
                out = f.read()
        finally:
            shutil.rmtree(tmpd, ignore_errors=True)
        if len(out) > MAX_OUT:
            raise ProductError("output %d bytes exceeds cap %d"
                               % (len(out), MAX_OUT))
        return {"in_bytes": len(data), "out_bytes": len(out),
                "sha256_in": _sha(data), "sha256_out": _sha(out),
                "target": target, "ext": ext,
                "payload_b64": base64.b64encode(out).decode("ascii")}
    if product == "cuni" and op == "ingest":
        frm = (params.get("from") or "").strip().lower()
        if not re.fullmatch(r"[a-z0-9]+", frm or ""):
            raise InputError("query param ?from=<ext> is required, "
                             "e.g. ?from=py")
        path = _check_bin("cuni")
        tmpd = tempfile.mkdtemp(prefix="x402-")
        try:
            src = os.path.join(tmpd, "prog." + frm)
            outp = os.path.join(tmpd, "out.cuni")
            with open(src, "wb") as f:
                f.write(data)
            try:
                p = subprocess.run([path, "ingest", src, "-o", outp],
                                   capture_output=True, timeout=120)
            except subprocess.TimeoutExpired:
                raise ProductError("cuni ingest timed out after 120s")
            if p.returncode != 0 or not os.path.isfile(outp):
                err = ((p.stderr or p.stdout) or b"").decode(
                    "utf-8", "replace")[:500]
                return {"refused": True, "from": frm,
                        "in_bytes": len(data), "sha256_in": _sha(data),
                        "reason": err or "ingest refused for .%s" % frm}
            with open(outp, "rb") as f:
                out = f.read()
        finally:
            shutil.rmtree(tmpd, ignore_errors=True)
        return {"in_bytes": len(data), "out_bytes": len(out),
                "sha256_in": _sha(data), "sha256_out": _sha(out),
                "from": frm,
                "payload_b64": base64.b64encode(out).decode("ascii")}
    if product == "trustream" and op == "info":
        return {"product": "trustream",
                "tile_bytes": 4096,
                "ops": ["ZERO", "MATH", "STORE"],
                "note": "PHRASE is reserved and refuses; busy tiles are "
                        "stored verbatim so the stream never inflates",
                "reference": "49,152 -> 20,518 bytes, 7/7 tests, "
                             "exact SHA-256 round-trip"}
    if product == "trustream" and op == "pack":
        try:
            packed = trustream_mod.encode_stream(data)
        except Exception as e:
            raise ProductError("trustream pack failed: %s" % str(e)[:200])
        counts = {}
        try:
            for tag, _tl, _fb in trustream_mod.tile_ops(packed):
                name = trustream_mod.TAG_NAME.get(tag, "0x%02x" % tag)
                counts[name] = counts.get(name, 0) + 1
        except Exception:
            pass
        if len(packed) > MAX_OUT:
            raise ProductError("output %d bytes exceeds cap %d"
                               % (len(packed), MAX_OUT))
        return {"in_bytes": len(data), "out_bytes": len(packed),
                "sha256_in": _sha(data), "sha256_out": _sha(packed),
                "tiles": counts,
                "ratio": round(len(packed) / len(data), 4) if data else 0.0,
                "payload_b64": base64.b64encode(packed).decode("ascii")}
    if product == "trustream" and op == "unpack":
        try:
            raw = trustream_mod.decode_stream(data)
        except Exception as e:
            raise InputError("not a valid TRUSTREAM stream: %s" % str(e)[:200])
        if len(raw) > MAX_OUT:
            raise ProductError("output %d bytes exceeds cap %d"
                               % (len(raw), MAX_OUT))
        return {"in_bytes": len(data), "out_bytes": len(raw),
                "sha256_in": _sha(data), "sha256_out": _sha(raw),
                "payload_b64": base64.b64encode(raw).decode("ascii")}
    if product == "pcc" and op == "compress":
        return _codec_roundtrip("pccx", data, "encode")
    if product == "pcc" and op == "decompress":
        return _codec_roundtrip("pccx", data, "decode")
    if product == "slidx" and op == "compress":
        return _codec_roundtrip("slidx", data, "encode")
    if product == "slidx" and op == "decompress":
        return _codec_roundtrip("slidx", data, "decode")
    raise ProductError("unknown product/op")


# --------------------------------------------------------------------------
# 402 requirements
# --------------------------------------------------------------------------
def _evm_howto(cents, rail, net, resource):
    return ("1) transfer >= %d¢ native USDC on %s to %s  "
            "2) sign this EXACT text with the paying address "
            "(EIP-191 personal_sign, e.g. ethers signMessage / "
            "MetaMask personal_sign):\n"
            "rider-x402 payment proof\\n"
            "txHash: <your 0x txhash, lowercase>\\n"
            "resource: %s  "
            "3) retry this request with header "
            "X-PAYMENT: base64url(JSON({\"x402Version\":2,"
            "\"scheme\":\"txHash\",\"network\":%s,"
            "\"payload\":{\"txHash\":\"0x...\",\"payerSig\":\"0x...\"}})). "
            "The payerSig binds the proof to you so nobody can "
            "front-run your txHash. Sign with the address that sent the "
            "USDC (for 4337 smart accounts that is the token sender, not "
            "the bundler); contract wallets verify via ERC-1271."
            % (cents, rail["label"], PAY_TO, resource, json.dumps(net)))


def payment_requirements(product, op, host, reason=None):
    cents = PRODUCTS[product][op]
    units = cents * UNITS_PER_CENT
    resource = "https://%s/api/x402/%s/%s" % (host, product, op)
    accepts = []
    for net, rail in EVM_RAILS.items():
        accepts.append({
            "scheme": PAY_SCHEME,
            "network": net,
            "amount": str(units),
            "asset": rail["usdc"],
            "payTo": PAY_TO,
            "resource": resource,
            "description": ("Slid Phi Labs %s %s — %d¢ native USDC on %s "
                            "per call" % (product, op, cents, rail["label"])),
            "mimeType": "application/json",
            "maxTimeoutSeconds": 300,
            "extra": {
                "paymentProof": "txHash",
                "howto": _evm_howto(cents, rail, net, resource),
            },
        })
    if PAY_TO_SOL:
        accepts.append({
            "scheme": PAY_SCHEME,
            "network": SOLANA_NETWORK,
            "amount": str(units),
            "asset": SOL_USDC_MINT,
            "payTo": PAY_TO_SOL,
            "resource": resource,
            "description": ("Slid Phi Labs %s %s — %d¢ SPL USDC on Solana "
                            "per call" % (product, op, cents)),
            "mimeType": "application/json",
            "maxTimeoutSeconds": 300,
            "extra": {
                "paymentProof": "signature",
                "howto": ("1) transfer >= %d¢ SPL USDC on Solana mainnet "
                          "to %s  2) retry this request with header "
                          "X-PAYMENT: base64url(JSON({\"x402Version\":2,"
                          "\"scheme\":\"txHash\",\"network\":%s,"
                          "\"payload\":{\"signature\":\"<base58>\"}}))"
                          % (cents, PAY_TO_SOL,
                             json.dumps(SOLANA_NETWORK))),
            },
        })
    if PAY_TO_BTC:
        # BTC is priced live (sats, rounded up). If the price feed is down
        # the rail is skipped for this challenge rather than mispriced.
        try:
            btc_price = btc_mod.btc_usd_price()
            btc_sats = btc_mod.sats_for_cents(cents, btc_price)
        except Exception:
            btc_price, btc_sats = 0.0, 0
        if btc_sats:
            accepts.append({
                "scheme": PAY_SCHEME,
                "network": BITCOIN_NETWORK,
                "amount": str(btc_sats),
                "asset": BITCOIN_ASSET,
                "payTo": PAY_TO_BTC,
                "resource": resource,
                "description": ("Slid Phi Labs %s %s — %d¢ in native BTC "
                                "on Bitcoin mainnet per call "
                                "(%d sats @ $%.2f/BTC)"
                                % (product, op, cents, btc_sats, btc_price)),
                "mimeType": "application/json",
                "maxTimeoutSeconds": 600,
                "extra": {
                    "paymentProof": "txid",
                    "btc_usd": btc_price,
                    "howto": ("1) send >= %d sats native BTC on Bitcoin "
                              "mainnet to %s (fees are on you and will "
                              "exceed this micro-payment)  2) sign this "
                              "EXACT text with the paying address (Bitcoin "
                              "signed message):\nrider-x402 payment proof\\n"
                              "txHash: <your txid, lowercase>\\nresource: %s "
                              "3) wait for 1 confirmation, then retry with "
                              "X-PAYMENT: base64url(JSON({\"x402Version\":2,"
                              "\"scheme\":\"txHash\",\"network\":%s,"
                              "\"payload\":{\"txid\":\"...\","
                              "\"payerSig\":\"<base64>\"}}))"
                              % (btc_sats, PAY_TO_BTC, resource,
                                 json.dumps(BITCOIN_NETWORK))),
                },
            })
    body = {
        "x402Version": X402_VERSION,
        "error": ("payment required: pay %d¢ USDC on a supported rail, "
                  "then retry with X-PAYMENT" % cents),
        "accepts": accepts,
        "extensions": {
            "refund": refund_mod.refund_extension_info(host),
        },
    }
    if reason:
        body["reason"] = reason
    return body


def payment_required_header(product, op, host, reason=None):
    """Value for the PAYMENT-REQUIRED header: base64url of the v2
    PaymentRequirements object, so standard x402 clients can read terms
    straight from the header without parsing the body."""
    req = payment_requirements(product, op, host, reason)
    return base64.urlsafe_b64encode(json.dumps(req).encode()).decode("ascii")


def parse_x_payment(header_value):
    """Extract (proof, network, payer_sig) from the X-PAYMENT header.

    Returns (proof, network, payer_sig, error). proof is a txHash on EVM
    rails and a base58 signature on Solana. payer_sig is the EIP-191
    personal_sign binding signature on EVM rails (None on Solana).
    Missing network means legacy Base callers.
    """
    if not header_value:
        return None, None, None, "missing X-PAYMENT header"
    try:
        padded = header_value.strip() + "=" * (-len(header_value.strip()) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError) as e:
        return None, None, None, \
            "X-PAYMENT is not valid base64url JSON: %s" % str(e)[:80]
    if not isinstance(payload, dict):
        return None, None, None, "X-PAYMENT payload must be a JSON object"
    scheme = payload.get("scheme")
    if scheme not in (None, "exact", PAY_SCHEME):
        return None, None, None, (
            "unsupported scheme %r: this server verifies txHash proofs "
            "(scheme %r). Standard EIP-3009 authorizations are not accepted; "
            "see the 402 body 'extra.howto'" % (scheme, PAY_SCHEME))
    net = payload.get("network") or NETWORK_CAIP2
    if net == "base":
        net = NETWORK_CAIP2
    inner = payload.get("payload") if isinstance(payload.get("payload"), dict) \
        else payload
    if net in EVM_RAILS:
        txh = inner.get("txHash") or inner.get("tx_hash")
        if not txh:
            return None, None, None, "X-PAYMENT payload needs payload.txHash"
        # Front-running protection: the proof must be bound to the payer.
        # payerSig = EIP-191 personal_sign by the paying address over
        # ethsig.binding_message(txHash, resource). Without it anyone
        # watching payTo on-chain could replay someone else's txHash first.
        psig = inner.get("payerSig") or inner.get("payer_sig")
        if not psig:
            return None, None, None, (
                "X-PAYMENT payload needs payload.payerSig: EIP-191 "
                "personal_sign (e.g. ethers signMessage) by the paying "
                "address over the binding message shown in extra.howto. "
                "This stops anyone replaying your txHash ahead of you.")
        return txh, net, psig, None
    if net == SOLANA_NETWORK:
        if not PAY_TO_SOL:
            return None, None, None, "Solana rail not enabled on this server"
        sig = inner.get("signature")
        if not sig:
            return None, None, None, "X-PAYMENT payload needs payload.signature"
        return sig, net, None, None
    if net == BITCOIN_NETWORK:
        if not PAY_TO_BTC:
            return None, None, None, "Bitcoin rail not enabled on this server"
        txid = inner.get("txid") or inner.get("txHash") or inner.get("tx_hash")
        if not txid:
            return None, None, None, "X-PAYMENT payload needs payload.txid"
        psig = inner.get("payerSig") or inner.get("payer_sig")
        if not psig:
            return None, None, None, (
                "X-PAYMENT payload needs payload.payerSig: base64 Bitcoin "
                "signed message by a funding input address over the binding "
                "message shown in extra.howto.")
        return txid, net, psig, None
    return None, None, None, ("unsupported network %r (supported: %s)"
                        % (net, ", ".join(list(EVM_RAILS) +
                                          ([SOLANA_NETWORK] if PAY_TO_SOL else []) +
                                          ([BITCOIN_NETWORK] if PAY_TO_BTC else []))))


# --------------------------------------------------------------------------
# refund extension routes (specs/extensions/refund.md)
# --------------------------------------------------------------------------

REFUND_SIGNER_KEY = os.environ.get("X402_REFUND_SIGNER_KEY", "").strip()


def _refund_ctx():
    """Build the process_refund context from live server config."""
    return {
        "pay_to": PAY_TO,
        "rails": EVM_RAILS,
        "transfer_topic": TRANSFER_TOPIC,
        "rpc_call": None,  # None -> process_refund raises; wired below
        "now": int(time.time()),
        "window_seconds": refund_mod.REFUND_WINDOW_SECONDS,
        "partial_refunds": True,
        "max_refund_units": None,
        "signer_key": REFUND_SIGNER_KEY or None,
        "broadcast": refund_mod.broadcast_refund_tx,
    }


def _live_rpc_call(method, params):
    """Default RPC dispatcher: Base rail URLs (refunds are EVM-only here)."""
    return _rpc_any(method, params, RPC_URLS)


def handle_refund_post(body_bytes, host):
    """POST /x402/refund. Returns (http_code, response_dict).

    Crash-safe ordering: reserve (verify + debit totals + cache the
    "broadcasting" marker) -> persist -> broadcast -> finalize/release ->
    persist. A crash between persist and finalize leaves the reservation
    and marker on disk, so a retried idempotency key can never trigger a
    second transfer; the client polls GET /x402/refund/{key}.
    """
    try:
        body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
    except (ValueError, UnicodeDecodeError):
        return 400, {"error": "body must be JSON"}
    req, perr = refund_mod.parse_refund_request(body)
    if perr:
        return 400, {"error": perr}
    ctx = _refund_ctx()
    ctx["rpc_call"] = _live_rpc_call
    with _state_lock:
        state = load_state()
        ctx["state"] = state
        try:
            ticket = refund_mod.reserve_refund(req, ctx)
        except refund_mod.RefundError as e:
            save_state(state)  # persist cached denial
            return 402, refund_mod.denial_response(req, e)
        if "replay" in ticket:
            return 200, ticket["replay"]
        save_state(state)  # reservation on disk BEFORE any money moves
    # broadcast outside the lock (network IO); the reservation + marker
    # already protect against duplicate execution.
    try:
        refund_tx = ctx["broadcast"](ticket["network"], ticket["dest"],
                                     ticket["amount_units"], ticket["asset"])
    except Exception as e:
        with _state_lock:
            state = load_state()
            ctx["state"] = state
            refund_mod.release_refund(ticket, ctx)
            save_state(state)
        log_call({"op": "refund", "ok": False,
                  "error": "broadcast: " + str(e)[:200]})
        return 500, {"error": str(e)[:300]}
    with _state_lock:
        state = load_state()
        ctx["state"] = state
        resp = refund_mod.finalize_refund(ticket, ctx, refund_tx)
        save_state(state)
    log_call({"op": "refund", "ok": True, "status": resp.get("status"),
              "amount": resp.get("amount"),
              "refund_tx": resp.get("refundTxHash")})
    return 200, resp


def handle_refund_status(idem_key):
    """GET /x402/refund/<idempotencyKey>: poll a queued/completed refund."""
    with _state_lock:
        state = load_state()
        cached = state.get("refund_idem", {}).get(idem_key)
    if cached is None:
        return 404, {"error": "unknown idempotencyKey"}
    return 200, dict(cached)


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
_rate = {}
_rate_lock = threading.Lock()


def rate_ok(ip):
    now = time.time()
    with _rate_lock:
        hits = _rate.get(ip, [])
        hits = [t for t in hits if now - t < 60]
        if len(hits) >= 120:
            return False
        hits.append(now)
        _rate[ip] = hits
        return True


OPENAPI = {
    "openapi": "3.0.3",
    "info": {
        "title": "Slid Phi Labs — Agent Rider x402 API",
        "version": "1.0.0",
        "description": ("Per-call USDC metering (multi-rail: Base, Polygon, "
                        "Arbitrum One, Optimism, Solana) for the lab's "
                        "compression products. Unpaid POSTs (and GETs on paid "
                        "routes) return 402 with x402 v2 PaymentRequirements "
                        "listing every supported rail. Paid callers retry with an "
                        "X-PAYMENT header carrying base64url JSON "
                        "{\"x402Version\":2,\"scheme\":\"txHash\","
                        "\"network\":\"<caip2>\","
                        "\"payload\":{\"txHash\":\"0x...\",\"payerSig\":\"0x...\"}} (EVM) or "
                        "{\"payload\":{\"signature\":\"<base58>\"}} (Solana) "
                        "proving a USDC transfer to the lab wallet. txHash / "
                        "signature proof is used instead of an EIP-3009 "
                        "meta-transaction: the payer pays their own gas and "
                        "the server settles nothing. The scheme is named "
                        "\"txHash\", not \"exact\", so standard x402 clients "
                        "don't try a signed authorization and loop."),
    },
    "servers": [{"url": "https://rider-x402.fly.dev"}],
    "paths": {},
}


def _build_openapi_paths():
    paths = {
        "/": {"get": {"summary": "Service info",
                      "responses": {"200": {"description": "info"}}}},
        "/health": {"get": {"summary": "Health check",
                            "responses": {"200": {"description": "ok"}}}},
        "/api/x402/prices": {"get": {"summary": "Price table (free)",
                                     "responses": {"200": {"description": "prices"}}}},
        "/openapi.json": {"get": {"summary": "This OpenAPI document",
                                  "responses": {"200": {"description": "spec"}}}},
        "/.well-known/x402": {"get": {"summary": "x402 route listing for indexers",
                                      "responses": {"200": {"description": "routes"}}}},
        "/x402/refund": {"post": {
            "summary": "x402 refund extension: request a refund of a settled payment",
            "description": ("Signed RefundRequest per specs/extensions/refund.md. "
                            "Only the original payer's signature is accepted; "
                            "amounts can't exceed settled-minus-refunded; "
                            "idempotency keys dedupe. See the 402 "
                            "PaymentRequired.extensions.refund for terms."),
            "requestBody": {"required": True,
                            "content": {"application/json": {
                                "schema": {"type": "object"}}}},
            "responses": {
                "200": {"description": "RefundResponse: executed"},
                "400": {"description": "malformed RefundRequest"},
                "402": {"description": "RefundResponse: denied (denialReason)"},
                "500": {"description": "refund broadcast not configured"},
            }}},
        "/x402/refund/{idempotencyKey}": {"get": {
            "summary": "Poll a refund by idempotency key",
            "parameters": [{"name": "idempotencyKey", "in": "path",
                            "required": True,
                            "schema": {"type": "string", "format": "uuid"}}],
            "responses": {
                "200": {"description": "cached RefundResponse"},
                "404": {"description": "unknown idempotencyKey"},
            }}},
    }
    pay_param = {
        "name": "X-PAYMENT", "in": "header", "required": False,
        "schema": {"type": "string"},
        "description": ("base64url JSON {\"x402Version\":2,\"scheme\":\"txHash\","
                        "\"network\":\"<one of eip155:8453, eip155:137, "
                        "eip155:42161, eip155:10, "
                        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp>\","
                        "\"payload\":{\"txHash\":\"0x...\"}} on EVM or "
                        "\"payload\":{\"signature\":\"<base58>\"}} on Solana. "
                        "Scheme \"exact\" also accepted for older integrators. "
                        "Omit it and the server answers 402 with payment terms."),
    }
    for product, ops in PRODUCTS.items():
        for op, cents in ops.items():
            params = [pay_param] + QUERY_PARAMS.get((product, op), [])
            paths["/api/x402/%s/%s" % (product, op)] = {
                "get": {
                    "summary": ("%s %s — %d¢ USDC per call (terms only)" % (product, op, cents)),
                    "parameters": params,
                    "responses": {
                        "402": {"description": "PaymentRequirements JSON (terms)"},
                    },
                },
                "post": {
                    "summary": "%s %s — %d¢ USDC per call" % (product, op, cents),
                    "parameters": params,
                    "requestBody": {
                        "required": (product, op) in DATA_OPS,
                        "content": {"application/json": {
                            "schema": {"type": "object",
                                       "properties": {"data": {"type": "string",
                                                               "description": "base64 input"}}}}},
                    },
                    "responses": {
                        "200": {"description": "product result"},
                        "402": {"description": "PaymentRequirements JSON"},
                        "400": {"description": "bad request"},
                    },
                }
            }
    return paths


OPENAPI["paths"] = _build_openapi_paths()


def _well_known():
    """Body for /.well-known/x402 — picked up by x402 indexers."""
    eps = {}
    for pr, ops in PRODUCTS.items():
        for op, cents in ops.items():
            eps["/api/x402/%s/%s" % (pr, op)] = {
                "cents_usdc": cents,
                "networks": (list(EVM_RAILS) +
                             ([SOLANA_NETWORK] if PAY_TO_SOL else []) +
                             ([BITCOIN_NETWORK] if PAY_TO_BTC else [])),
                "scheme": PAY_SCHEME,
                "x402Version": X402_VERSION,
            }
    return {"service": "rider-x402",
            "x402Version": X402_VERSION,
            "paymentHeader": "X-PAYMENT",
            "networks": _rail_info(),
            "endpoints": eps}


class Handler(BaseHTTPRequestHandler):
    server_version = "rider-x402/1.1"

    def _send(self, code, obj, extra_headers=None, head_only=False):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _path(self):
        return self.path.split("?", 1)[0].rstrip("/") or "/"

    def _query(self):
        parts = self.path.split("?", 1)
        if len(parts) < 2:
            return {}
        return dict(urllib.parse.parse_qsl(parts[1], keep_blank_values=True))

    def log_message(self, fmt, *args):  # quiet; we keep our own audit log
        pass

    def _redirect_short_path(self, head_only=False):
        """Redirect /api/<product>/<op> (missing the /x402/ segment — the
        path a published quick-test used) to /api/x402/<product>/<op>.
        308 keeps the method so POST quick-tests survive the hop."""
        m = re.fullmatch(r"/api/([a-z]+)/([a-z]+)", self._path())
        if m and m.group(1) in PRODUCTS and m.group(2) in PRODUCTS[m.group(1)]:
            target = "/api/x402/%s/%s" % (m.group(1), m.group(2))
            self.send_response(308)
            self.send_header("Location", target)
            body = json.dumps({"redirect": target}).encode()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if not head_only:
                self.wfile.write(body)
            return True
        return False

    def _route_get(self, head_only=False):
        p = self._path()
        if p == "/":
            eps = ["/api/x402/%s/%s (%d¢)" % (pr, op, c)
                   for pr, ops in PRODUCTS.items() for op, c in ops.items()]
            return self._send(200, {"service": "rider-x402",
                                    "x402Version": X402_VERSION,
                                    "networks": _rail_info(),
                                    "endpoints": eps,
                                    "usage": "POST an endpoint; unpaid -> 402 with terms"},
                              head_only=head_only)
        if p == "/health":
            return self._send(200, {"ok": True, "ts": int(time.time())},
                              head_only=head_only)
        if p == "/api/x402/prices":
            return self._send(200, {"networks": _rail_info(),
                                    "prices_usdc_cents": {pr: ops for pr, ops in PRODUCTS.items()}},
                              head_only=head_only)
        if p == "/openapi.json":
            return self._send(200, OPENAPI, head_only=head_only)
        if p == "/.well-known/x402":
            return self._send(200, _well_known(), head_only=head_only)
        m = re.fullmatch(r"/x402/refund/([0-9a-fA-F-]{36})", p)
        if m:
            # x402 refund extension: poll a refund by idempotency key
            code, resp = handle_refund_status(m.group(1).lower())
            return self._send(code, resp, head_only=head_only)
        m = re.fullmatch(r"/api/x402/([a-z]+)/([a-z]+)", p)
        if m and m.group(1) in PRODUCTS and m.group(2) in PRODUCTS[m.group(1)]:
            # Paid route over GET: answer 402 with the terms, so scanners
            # and indexers see a live payment gate instead of a dead host.
            product, op = m.group(1), m.group(2)
            host = self.headers.get("Host", "rider-x402.fly.dev")
            return self._send(402, payment_requirements(product, op, host),
                              {"PAYMENT-REQUIRED":
                               payment_required_header(product, op, host)},
                              head_only=head_only)
        return self._send(404, {"error": "not found"}, head_only=head_only)

    def do_GET(self):
        if self._redirect_short_path():
            return
        return self._route_get()

    def do_HEAD(self):
        if self._redirect_short_path(head_only=True):
            return
        return self._route_get(head_only=True)

    def do_POST(self):
        p = self._path()
        if self._redirect_short_path():
            return
        if p == "/x402/refund":
            # x402 refund extension: signed RefundRequest -> RefundResponse
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_IN:
                return self._send(413, {"error": "body too large"})
            raw = self.rfile.read(length) if length else b""
            host = self.headers.get("Host", "rider-x402.fly.dev")
            code, resp = handle_refund_post(raw, host)
            return self._send(code, resp)
        m = re.fullmatch(r"/api/x402/([a-z]+)/([a-z]+)", p)
        if not m or m.group(1) not in PRODUCTS or m.group(2) not in PRODUCTS[m.group(1)]:
            return self._send(404, {"error": "unknown endpoint; see GET /openapi.json"})
        product, op = m.group(1), m.group(2)
        cents = PRODUCTS[product][op]
        ip = self.client_address[0]
        if not rate_ok(ip):
            return self._send(429, {"error": "rate limited, slow down"})

        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_IN + 1024:
            return self._send(413, {"error": "body too large"})
        raw = self.rfile.read(length) if length else b""
        entry = {"ip": ip, "product": product, "op": op, "cents": cents}

        # ---- payment gate ----
        host = self.headers.get("Host", "rider-x402.fly.dev")
        proof, net, payer_sig, perr = parse_x_payment(self.headers.get("X-PAYMENT"))
        if perr:
            entry.update(ok=False, error="402: " + perr)
            log_call(entry)
            return self._send(402, payment_requirements(product, op, host,
                                                        reason=perr),
                              {"PAYMENT-REQUIRED":
                               payment_required_header(product, op, host,
                                                       reason=perr)})
        entry["network"] = net
        resource = "https://%s/api/x402/%s/%s" % (host, product, op)
        with _state_lock:
            state = load_state()
            used = set(state["used_tx"])
            ok, info = verify_payment(proof, net, cents * UNITS_PER_CENT, used,
                                      payer_sig=payer_sig, resource=resource)
            state["used_tx"] = sorted(used)[-20000:]
            save_state(state)
        if not ok:
            vreason = info.get("reason", "payment not verified")
            entry.update(ok=False, error="402: " + vreason)
            log_call(entry)
            return self._send(402, payment_requirements(product, op, host,
                                                        reason=vreason),
                              {"PAYMENT-REQUIRED":
                               payment_required_header(product, op, host,
                                                       reason=vreason)})
        entry.update(paid_units=info["paid_units"], tx=info["tx"])

        # ---- run product ----
        data = None
        if (product, op) in DATA_OPS:
            try:
                body = json.loads(raw.decode("utf-8")) if raw else {}
                data = base64.b64decode((body.get("data") or "").strip(),
                                        validate=True)
            except (ValueError, binascii.Error):
                entry.update(ok=False, error="bad body: data must be base64")
                log_call(entry)
                return self._send(400, {"error": "body must be JSON {\"data\": \"<base64>\"}"})
        try:
            result = run_product(product, op, data, self._query())
        except InputError as e:
            entry.update(ok=False, error="input: " + str(e)[:200])
            log_call(entry)
            return self._send(400, {"error": str(e)[:500]})
        except ProductError as e:
            entry.update(ok=False, error="product: " + str(e)[:200])
            log_call(entry)
            return self._send(500, {"error": str(e)[:500]})
        entry.update(ok=True, out_bytes=result.get("out_bytes"),
                     in_bytes=result.get("in_bytes"))
        log_call(entry)
        resp_h = {"X-PAYMENT-RESPONSE": base64.urlsafe_b64encode(
            json.dumps({"x402Version": X402_VERSION, "success": True,
                        "transaction": info["tx"],
                        "network": info.get("network", net)}).encode()).decode()}
        return self._send(200, {"ok": True, "product": product, "op": op,
                                "charged_cents": cents,
                                "charged_units": (btc_mod.sats_for_cents(cents)
                                                  if net == BITCOIN_NETWORK
                                                  else cents * UNITS_PER_CENT),
                                "tx": info["tx"], "result": result},
                          resp_h)


def main():
    if not PAY_TO:
        raise SystemExit("X402_PAY_TO env required")
    if not RPC_URLS:
        raise SystemExit("X402_RPC_URLS env required")
    if PAY_TO_BTC and not btc_mod.is_valid_btc_address(PAY_TO_BTC):
        raise SystemExit("X402_PAY_TO_BTC is not a valid Bitcoin address")
    os.makedirs(os.path.join(SRV_DIR, "bin"), exist_ok=True)
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("rider-x402 listening on :%d (pay_to=%s)" % (PORT, PAY_TO), flush=True)
    print("rails: %s" % ", ".join("%s %s" % (r["label"], r["network"])
                                  for r in _rail_info()), flush=True)
    if not PAY_TO_SOL:
        print("note: X402_PAY_TO_SOL unset — Solana rail not advertised",
              flush=True)
    if not PAY_TO_BTC:
        print("note: X402_PAY_TO_BTC unset — Bitcoin rail not advertised",
              flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
