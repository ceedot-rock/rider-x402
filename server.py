#!/usr/bin/env python3
"""rider-x402: HTTP 402 endpoint for Agent Rider products (Slid Phi Labs).

Unpaid callers get `402 Payment Required` with an x402-style
PaymentRequirements JSON body (<300ms, no chain IO) plus a
`PAYMENT-REQUIRED` header for Circle's health checkers.

Paid callers retry with:
    X-PAYMENT: base64url(JSON({
        "x402Version": 1,
        "scheme": "exact",
        "network": "eip155:8453",
        "payload": {"txHash": "0x..."}
    }))
proving a Base USDC transfer to the lab wallet. The tx is verified
on-chain (format, replay, receipt exists + ok, real USDC Transfer events
paying the lab address >= price) and each txhash is accepted once.
NOTE: this endpoint uses txhash proof rather than an EIP-3009 meta-tx,
so the payer pays their own gas and we settle nothing. The payment TERMS
(amount/asset/network/payTo) are standard x402 `exact` terms.

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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import awareness as awareness_mod

# Canonical native USDC on Base mainnet (6 decimals), verified against
# Circle's official docs 2026-09-24. Do not change without Corey's say-so.
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
TRANSFER_TOPIC = ("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a"
                  "4df523b3ef")
USDC_DECIMALS = 6
UNITS_PER_CENT = 10 ** (USDC_DECIMALS - 2)

NETWORK_CAIP2 = "eip155:8453"
X402_VERSION = 1

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
    return info

SRV_DIR = os.environ.get("SRV_DIR", "/srv")
PORT = int(os.environ.get("PORT", "8080"))
PAY_TO = os.environ.get("X402_PAY_TO", "").strip()
PAY_TO_SOL = os.environ.get("X402_PAY_TO_SOL", "").strip()
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
    "cuni": {"check": 10, "seats": 2},
    "awareness": {"scan": 10},
}
DATA_OPS = {("pcc", "compress"), ("pcc", "decompress"),
            ("slidx", "compress"), ("slidx", "decompress"),
            ("cuni", "check"), ("awareness", "scan")}


class ProductError(Exception):
    pass


# --------------------------------------------------------------------------
# state (persistent used-txhash set)
# --------------------------------------------------------------------------
_state_lock = threading.Lock()


def load_state():
    try:
        with open(STATE_PATH) as f:
            s = json.load(f)
            return {"used_tx": s.get("used_tx", [])}
    except (FileNotFoundError, ValueError):
        return {"used_tx": []}


def save_state(state):
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"used_tx": sorted(state["used_tx"])[-20000:]}, f)
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


def _verify_evm(tx_hash, network, rail, min_units, used_set, rpc=None):
    """Exact same shape as the original Base check, per-chain config."""
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
    paid = _sum_usdc_to(receipt, PAY_TO, rail["usdc"])
    if paid < min_units:
        return False, {"reason": "underpaid: got %.6f USDC, need %.6f"
                                 % (paid / 10 ** USDC_DECIMALS,
                                    min_units / 10 ** USDC_DECIMALS),
                       "paid_units": paid}
    used_set.add(key)
    return True, {"paid_units": paid, "tx": h, "network": network}


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


def verify_payment(proof, network, min_units, used_set, rpc=None):
    """Returns (ok, info). On success the namespaced proof is added to used_set."""
    if network == SOLANA_NETWORK:
        return _verify_solana(proof, min_units, used_set, rpc)
    rail = EVM_RAILS.get(network)
    if not rail:
        return False, {"reason": "unsupported network %r" % (network,)}
    return _verify_evm(proof, network, rail, min_units, used_set, rpc)


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


def run_product(product, op, data):
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
        path = _check_bin("cuni")
        p = _run([path, "--list-langs"], timeout=15)
        lines = [l for l in p.stdout.decode("utf-8", "replace").splitlines()
                 if l.strip()]
        return {"seat_count": len(lines), "sample": lines[:12],
                "note": "remaining seats run via Python lowering"}
    if product == "pcc" and op == "compress":
        return _codec_roundtrip("pccx", data, "encode")
    if product == "pcc" and op == "decompress":
        return _codec_roundtrip("pccx", data, "decode")
    if product == "slidx" and op == "compress":
        return _codec_roundtrip("slidx", data, "encode")
    if product == "slidx" and op == "decompress":
        return _codec_roundtrip("slidx", data, "decode")
    if product == "cuni" and op == "check":
        path = _check_bin("cuni")
        tmpd = tempfile.mkdtemp(prefix="x402-")
        try:
            src = os.path.join(tmpd, "prog.cuni")
            with open(src, "wb") as f:
                f.write(data)
            p = _run([path, "check", src, "--only", "py", "--receipt"],
                     timeout=120)
        finally:
            shutil.rmtree(tmpd, ignore_errors=True)
        text = p.stdout.decode("utf-8", "replace")
        return {"in_bytes": len(data), "sha256_in": _sha(data),
                "exactness_pass": "exactness: PASS" in text,
                "harness_tail": "\n".join(text.splitlines()[-8:])}
    raise ProductError("unknown product/op")


# --------------------------------------------------------------------------
# 402 requirements
# --------------------------------------------------------------------------
def _evm_howto(cents, rail, net):
    return ("1) transfer >= %d¢ native USDC on %s to %s  "
            "2) retry this request with header "
            "X-PAYMENT: base64url(JSON({\"x402Version\":1,"
            "\"scheme\":\"exact\",\"network\":%s,"
            "\"payload\":{\"txHash\":\"0x...\"}}))"
            % (cents, rail["label"], PAY_TO, json.dumps(net)))


def payment_requirements(product, op, host):
    cents = PRODUCTS[product][op]
    units = cents * UNITS_PER_CENT
    resource = "https://%s/api/x402/%s/%s" % (host, product, op)
    accepts = []
    for net, rail in EVM_RAILS.items():
        accepts.append({
            "scheme": "exact",
            "network": net,
            "maxAmountRequired": str(units),
            "asset": rail["usdc"],
            "payTo": PAY_TO,
            "resource": resource,
            "description": ("Slid Phi Labs %s %s — %d¢ native USDC on %s "
                            "per call" % (product, op, cents, rail["label"])),
            "mimeType": "application/json",
            "maxTimeoutSeconds": 300,
            "extra": {
                "paymentProof": "txHash",
                "howto": _evm_howto(cents, rail, net),
            },
        })
    if PAY_TO_SOL:
        accepts.append({
            "scheme": "exact",
            "network": SOLANA_NETWORK,
            "maxAmountRequired": str(units),
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
                          "X-PAYMENT: base64url(JSON({\"x402Version\":1,"
                          "\"scheme\":\"exact\",\"network\":%s,"
                          "\"payload\":{\"signature\":\"<base58>\"}}))"
                          % (cents, PAY_TO_SOL,
                             json.dumps(SOLANA_NETWORK))),
            },
        })
    return {
        "x402Version": X402_VERSION,
        "error": ("payment required: pay %d¢ USDC on a supported rail, "
                  "then retry with X-PAYMENT" % cents),
        "accepts": accepts,
    }


def parse_x_payment(header_value):
    """Extract (proof, network) from the X-PAYMENT header.

    Returns (proof, network, error). proof is a txHash on EVM rails and a
    base58 signature on Solana. Missing network means legacy Base callers.
    """
    if not header_value:
        return None, None, "missing X-PAYMENT header"
    try:
        padded = header_value.strip() + "=" * (-len(header_value.strip()) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError) as e:
        return None, None, "X-PAYMENT is not valid base64url JSON: %s" % str(e)[:80]
    if not isinstance(payload, dict):
        return None, None, "X-PAYMENT payload must be a JSON object"
    net = payload.get("network") or NETWORK_CAIP2
    if net == "base":
        net = NETWORK_CAIP2
    inner = payload.get("payload") if isinstance(payload.get("payload"), dict) \
        else payload
    if net in EVM_RAILS:
        txh = inner.get("txHash") or inner.get("tx_hash")
        if not txh:
            return None, None, "X-PAYMENT payload needs payload.txHash"
        return txh, net, None
    if net == SOLANA_NETWORK:
        if not PAY_TO_SOL:
            return None, None, "Solana rail not enabled on this server"
        sig = inner.get("signature")
        if not sig:
            return None, None, "X-PAYMENT payload needs payload.signature"
        return sig, net, None
    return None, None, ("unsupported network %r (supported: %s)"
                        % (net, ", ".join(list(EVM_RAILS) +
                                          ([SOLANA_NETWORK] if PAY_TO_SOL else []))))


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
                        "compression products. Unpaid POSTs return 402 with "
                        "x402-style PaymentRequirements listing every "
                        "supported rail. Paid callers retry with an "
                        "X-PAYMENT header carrying base64url JSON "
                        "{\"x402Version\":1,\"scheme\":\"exact\","
                        "\"network\":\"<caip2>\","
                        "\"payload\":{\"txHash\":\"0x...\"}} (EVM) or "
                        "{\"payload\":{\"signature\":\"<base58>\"}} (Solana) "
                        "proving a USDC transfer to the lab wallet. txHash / "
                        "signature proof is used instead of an EIP-3009 "
                        "meta-transaction: the payer pays their own gas and "
                        "the server settles nothing."),
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
    }
    pay_param = {
        "name": "X-PAYMENT", "in": "header", "required": False,
        "schema": {"type": "string"},
        "description": ("base64url JSON {\"x402Version\":1,\"scheme\":\"exact\","
                        "\"network\":\"<one of eip155:8453, eip155:137, "
                        "eip155:42161, eip155:10, "
                        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp>\","
                        "\"payload\":{\"txHash\":\"0x...\"}} on EVM or "
                        "\"payload\":{\"signature\":\"<base58>\"}} on Solana. "
                        "Omit it and the server answers 402 with payment terms."),
    }
    for product, ops in PRODUCTS.items():
        for op, cents in ops.items():
            paths["/api/x402/%s/%s" % (product, op)] = {
                "post": {
                    "summary": "%s %s — %d¢ USDC per call" % (product, op, cents),
                    "parameters": [pay_param],
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


class Handler(BaseHTTPRequestHandler):
    server_version = "rider-x402/1.0"

    def _send(self, code, obj, extra_headers=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _path(self):
        return self.path.split("?", 1)[0].rstrip("/") or "/"

    def log_message(self, fmt, *args):  # quiet; we keep our own audit log
        pass

    def do_GET(self):
        p = self._path()
        if p == "/":
            eps = ["/api/x402/%s/%s (%d¢)" % (pr, op, c)
                   for pr, ops in PRODUCTS.items() for op, c in ops.items()]
            return self._send(200, {"service": "rider-x402",
                                    "x402Version": X402_VERSION,
                                    "networks": _rail_info(),
                                    "endpoints": eps,
                                    "usage": "POST an endpoint; unpaid -> 402 with terms"})
        if p == "/health":
            return self._send(200, {"ok": True, "ts": int(time.time())})
        if p == "/api/x402/prices":
            return self._send(200, {"networks": _rail_info(),
                                    "prices_usdc_cents": {pr: ops for pr, ops in PRODUCTS.items()}})
        if p == "/openapi.json":
            return self._send(200, OPENAPI)
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        p = self._path()
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
        proof, net, perr = parse_x_payment(self.headers.get("X-PAYMENT"))
        if perr:
            entry.update(ok=False, error="402: " + perr)
            log_call(entry)
            return self._send(402, payment_requirements(product, op,
                                                        self.headers.get("Host", "rider-x402.fly.dev")),
                              {"PAYMENT-REQUIRED": "1"})
        entry["network"] = net
        with _state_lock:
            state = load_state()
            used = set(state["used_tx"])
            ok, info = verify_payment(proof, net, cents * UNITS_PER_CENT, used)
            state["used_tx"] = sorted(used)[-20000:]
            save_state(state)
        if not ok:
            entry.update(ok=False, error="402: " + info.get("reason", "?"))
            log_call(entry)
            return self._send(402, payment_requirements(product, op,
                                                        self.headers.get("Host", "rider-x402.fly.dev")),
                              {"PAYMENT-REQUIRED": "1"})
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
            result = run_product(product, op, data)
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
                                "charged_units": cents * UNITS_PER_CENT,
                                "tx": info["tx"], "result": result},
                          resp_h)


def main():
    if not PAY_TO:
        raise SystemExit("X402_PAY_TO env required")
    if not RPC_URLS:
        raise SystemExit("X402_RPC_URLS env required")
    os.makedirs(os.path.join(SRV_DIR, "bin"), exist_ok=True)
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("rider-x402 listening on :%d (pay_to=%s)" % (PORT, PAY_TO), flush=True)
    print("rails: %s" % ", ".join("%s %s" % (r["label"], r["network"])
                                  for r in _rail_info()), flush=True)
    if not PAY_TO_SOL:
        print("note: X402_PAY_TO_SOL unset — Solana rail not advertised",
              flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
