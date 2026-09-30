#!/usr/bin/env python3
"""Tests for the x402 `refund` extension reference implementation.

Zero network: chain IO is injected via a fake RPC. The broadcast stub runs
in X402_REFUND_BROADCAST=test mode (deterministic fake hashes — no money).

Run:  python3 test_refund.py
"""
import hashlib
import json
import os
import sys
import time
import uuid

os.environ["X402_REFUND_BROADCAST"] = "test"
sys.path.insert(0, "/home/hatch/workspace/rider-x402")

import ethsig
import refund as R

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("  ok " if cond else "  FAIL ") + name
          + (" — " + str(detail)[:160] if detail and not cond else ""))


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------

def tkey(label):
    return "0x" + hashlib.sha256(label.encode()).hexdigest()


PAYER_KEY = tkey("refund-test:payer")
ATTACKER_KEY = tkey("refund-test:attacker")
SIGNER_KEY = tkey("refund-test:server-signer")
PAYER = "0x" + ethsig.privkey_to_address(PAYER_KEY).hex()
ATTACKER = "0x" + ethsig.privkey_to_address(ATTACKER_KEY).hex()
SIGNER = "0x" + ethsig.privkey_to_address(SIGNER_KEY).hex()
PAY_TO = "0x" + ethsig.privkey_to_address(tkey("refund-test:payto")).hex()
USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
NET = "eip155:8453"
TOPIC = ("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a"
         "4df523b3ef")
NOW = 1_789_000_000

TXH = "0x" + "ab" * 32
SETTLED_UNITS = 25_000  # 25 cents of USDC (6 decimals)
BLOCK_TS = NOW - 3600   # settled 1h ago: inside the 24h window


def topic_addr(a):
    return "0x" + "00" * 12 + a[2:].lower()


def transfer_log(frm, to, value):
    return {"address": USDC,
            "topics": [TOPIC, topic_addr(frm), topic_addr(to)],
            "data": hex(value)}


def make_rpc(payments):
    """payments: {txhash_lower: {"receipt": dict, "block_ts": int}}"""
    def call(method, params):
        if method == "eth_getTransactionReceipt":
            p = payments.get((params[0] or "").lower())
            return {"result": p["receipt"] if p else None}
        if method == "eth_getBlockByNumber":
            for p in payments.values():
                if p["receipt"].get("blockNumber") == params[0]:
                    return {"result": {"timestamp": hex(p["block_ts"])}}
            return {"result": None}
        raise AssertionError("unexpected rpc method " + method)
    return call


def receipt(txh, frm, to, value, block_ts, block_num="0x1234"):
    return {"status": "0x1", "blockNumber": block_num,
            "from": "0xbundle000000000000000000000000000000000001",
            "logs": [transfer_log(frm, to, value)]}


def ctx_for(payments, **over):
    c = {
        "pay_to": PAY_TO,
        "rails": {NET: {"usdc": USDC}},
        "transfer_topic": TOPIC,
        "rpc_call": make_rpc(payments),
        "now": NOW,
        "state": {"refund_totals": {}, "refund_idem": {}},
        "window_seconds": R.REFUND_WINDOW_SECONDS,
        "partial_refunds": True,
        "max_refund_units": None,
        "signer_key": SIGNER_KEY,
        "broadcast": R.broadcast_refund_tx,
    }
    c.update(over)
    return c


def req_for(txh=TXH, amount=SETTLED_UNITS, key=PAYER_KEY, reason="other",
            refund_to="", idem=None):
    body = {
        "x402Version": 2,
        "paymentReference": {"txHash": txh, "network": NET},
        "amount": str(amount),
        "reason": reason,
        "refundTo": refund_to,
        "idempotencyKey": idem or str(uuid.uuid4()),
    }
    sig = ethsig.sign_personal(R.canonical_refund_bytes(body), key)
    body["payerSignature"] = sig
    req, err = R.parse_refund_request(body)
    assert err is None, err
    return req


def payments(txh=TXH, value=SETTLED_UNITS, block_ts=BLOCK_TS):
    return {txh.lower(): {"receipt": receipt(txh, PAYER, PAY_TO, value,
                                             block_ts),
                          "block_ts": block_ts}}


def expect_denial(name, fn, want):
    try:
        fn()
    except R.RefundError as e:
        check(name, e.denial == want, "got %s" % e.denial)
        return
    check(name, False, "no denial raised")


# --------------------------------------------------------------------------
# 1. happy path
# --------------------------------------------------------------------------
c = ctx_for(payments())
req = req_for()
resp = R.process_refund(req, c)
check("happy path executes", resp["status"] == "executed", resp)
check("happy path amount", resp["amount"] == str(SETTLED_UNITS))
check("happy path fake tx hash", resp["refundTxHash"].startswith("0x")
      and len(resp["refundTxHash"]) == 66)
check("happy path totals updated",
      c["state"]["refund_totals"][NET + ":" + TXH] == SETTLED_UNITS)
rcpt = resp.get("refundReceipt")
check("refund receipt present", isinstance(rcpt, dict))
check("refund receipt signature verifies",
      R.verify_refund_receipt(rcpt, SIGNER))
check("refund receipt wrong signer fails",
      not R.verify_refund_receipt(rcpt, ATTACKER))
check("refund receipt payload fields",
      rcpt["payload"]["paymentTxHash"] == TXH
      and rcpt["payload"]["payer"] == PAYER
      and rcpt["payload"]["amount"] == str(SETTLED_UNITS))

# --------------------------------------------------------------------------
# 2. payer-signature rejection
# --------------------------------------------------------------------------
c = ctx_for(payments())
bad = req_for(key=ATTACKER_KEY)
expect_denial("wrong signer -> not_payer",
              lambda: R.process_refund(bad, c), "not_payer")

# tampered wire amount after signing -> signature no longer matches
c = ctx_for(payments())
tbody = {
    "x402Version": 2,
    "paymentReference": {"txHash": TXH, "network": NET},
    "amount": "1000",
    "reason": "other",
    "refundTo": "",
    "idempotencyKey": str(uuid.uuid4()),
}
tbody["payerSignature"] = ethsig.sign_personal(
    R.canonical_refund_bytes(tbody), PAYER_KEY)
tbody["amount"] = "999"  # attacker alters the amount post-sign
t, terr = R.parse_refund_request(tbody)
assert terr is None, terr
expect_denial("tampered amount -> not_payer",
              lambda: R.process_refund(t, c), "not_payer")

# --------------------------------------------------------------------------
# 3. double-refund prevention
# --------------------------------------------------------------------------
c = ctx_for(payments())
r1 = req_for(idem="11111111-1111-1111-1111-111111111111")
R.process_refund(r1, c)
r2 = req_for(idem="22222222-2222-2222-2222-222222222222")
expect_denial("second full refund -> already_refunded",
              lambda: R.process_refund(r2, c), "already_refunded")
check("totals unchanged after denied replay",
      c["state"]["refund_totals"][NET + ":" + TXH] == SETTLED_UNITS)

# --------------------------------------------------------------------------
# 4. idempotency replay: same key -> cached, no second broadcast
# --------------------------------------------------------------------------
calls = []
c = ctx_for(payments(),
            broadcast=lambda n, t, u, a: (calls.append((n, t, u, a)),
                                          R.broadcast_refund_tx(n, t, u, a))[1])
rk = "33333333-3333-3333-3333-333333333333"
ra = req_for(amount=10000, idem=rk)
resp_a = R.process_refund(ra, c)
resp_b = R.process_refund(ra, c)  # exact same request object, replayed
check("idempotent replay returns identical response", resp_a == resp_b,
      "%r vs %r" % (resp_a, resp_b))
check("idempotent replay broadcasts once", len(calls) == 1, calls)
check("idempotent replay totals counted once",
      c["state"]["refund_totals"][NET + ":" + TXH] == 10000)

# denial is cached too (except transient unknown_payment)
c = ctx_for(payments())
dk = "44444444-4444-4444-4444-444444444444"
d1 = req_for(amount=SETTLED_UNITS + 1, idem=dk)
try:
    R.process_refund(d1, c)
    check("over-cap denial raised", False)
except R.RefundError as e:
    check("over-cap denial cached",
          c["state"]["refund_idem"][dk]["denialReason"] == e.denial)
    # replaying the same key returns the CACHED denial response (spec:
    # a repeated key returns the original response, never a new transfer)
    resp_replay = R.process_refund(d1, c)
    check("denied key replay returns cached denial",
          resp_replay["status"] == "denied"
          and resp_replay["denialReason"] == "amount_exceeds_settled",
          resp_replay)

# --------------------------------------------------------------------------
# 5. window enforcement
# --------------------------------------------------------------------------
old_ts = NOW - R.REFUND_WINDOW_SECONDS - 1
c = ctx_for(payments(block_ts=old_ts))
expect_denial("payment older than window -> outside_window",
              lambda: R.process_refund(req_for(), c), "outside_window")

# exactly at the edge is still inside
edge_ts = NOW - R.REFUND_WINDOW_SECONDS
c = ctx_for(payments(block_ts=edge_ts))
try:
    R.process_refund(req_for(), c)
    check("payment at window edge accepted", True)
except R.RefundError as e:
    check("payment at window edge accepted", False, e.denial)

# --------------------------------------------------------------------------
# 6. partial refunds
# --------------------------------------------------------------------------
c = ctx_for(payments())
p1 = req_for(amount=10000, idem="55555555-5555-5555-5555-555555555555")
p2 = req_for(amount=15000, idem="66666666-6666-6666-6666-666666666666")
R.process_refund(p1, c)
R.process_refund(p2, c)
check("two partials sum to settled",
      c["state"]["refund_totals"][NET + ":" + TXH] == SETTLED_UNITS)
p3 = req_for(amount=1, idem="77777777-7777-7777-7777-777777777777")
expect_denial("third refund over total -> already_refunded",
              lambda: R.process_refund(p3, c), "already_refunded")

# partial exceeding remainder -> amount_exceeds_settled
c = ctx_for(payments())
R.process_refund(req_for(amount=20000,
                         idem="88888888-8888-8888-8888-888888888888"), c)
expect_denial("partial over remainder -> amount_exceeds_settled",
              lambda: R.process_refund(
                  req_for(amount=6000,
                          idem="99999999-9999-9999-9999-999999999999"), c),
              "amount_exceeds_settled")

# partial refunds disabled by policy
c = ctx_for(payments(), partial_refunds=False)
expect_denial("partial disabled -> policy_denied",
              lambda: R.process_refund(req_for(amount=10000), c),
              "policy_denied")
c = ctx_for(payments(), partial_refunds=False)
try:
    R.process_refund(req_for(amount=SETTLED_UNITS), c)
    check("full refund ok when partials disabled", True)
except R.RefundError as e:
    check("full refund ok when partials disabled", False, e.denial)

# --------------------------------------------------------------------------
# 7. unknown payment
# --------------------------------------------------------------------------
c = ctx_for({})
expect_denial("tx not found -> unknown_payment",
              lambda: R.process_refund(req_for(), c), "unknown_payment")
check("unknown_payment is NOT cached (transient)",
      c["state"]["refund_idem"] == {})

c = ctx_for(payments())
weird_net_req = req_for()
weird_net_req["paymentReference"] = {"txHash": TXH, "network": "eip155:999999",
                                     "paymentId": None}
expect_denial("unsupported network -> unknown_payment",
              lambda: R.process_refund(weird_net_req, c), "unknown_payment")

# reverted tx
bad_rcpt = receipt(TXH, PAYER, PAY_TO, SETTLED_UNITS, BLOCK_TS)
bad_rcpt["status"] = "0x0"
c = ctx_for({TXH.lower(): {"receipt": bad_rcpt, "block_ts": BLOCK_TS}})
expect_denial("reverted tx -> unknown_payment",
              lambda: R.process_refund(req_for(), c), "unknown_payment")

# no USDC to pay_to in logs
empty_rcpt = receipt(TXH, PAYER, ATTACKER, SETTLED_UNITS, BLOCK_TS)
c = ctx_for({TXH.lower(): {"receipt": empty_rcpt, "block_ts": BLOCK_TS}})
expect_denial("no transfer to pay_to -> unknown_payment",
              lambda: R.process_refund(req_for(), c), "unknown_payment")

# --------------------------------------------------------------------------
# 8. request validation (no chain IO)
# --------------------------------------------------------------------------
def bad_body(mutate):
    body = {
        "x402Version": 2,
        "paymentReference": {"txHash": TXH, "network": NET},
        "amount": str(100),
        "reason": "other",
        "idempotencyKey": str(uuid.uuid4()),
        "payerSignature": "0x" + "00" * 65,
    }
    mutate(body)
    _, err = R.parse_refund_request(body)
    return err

check("rejects bad version", bad_body(lambda b: b.update(x402Version=1)) is not None)
check("rejects bad txhash",
      bad_body(lambda b: b["paymentReference"].update(txHash="nope")) is not None)
check("rejects zero amount",
      bad_body(lambda b: b.update(amount="0")) is not None)
check("rejects negative amount",
      bad_body(lambda b: b.update(amount="-5")) is not None)
check("rejects bad reason",
      bad_body(lambda b: b.update(reason="nope")) is not None)
check("rejects bad idempotency key",
      bad_body(lambda b: b.update(idempotencyKey="nope")) is not None)
check("rejects missing payerSig",
      bad_body(lambda b: b.pop("payerSignature")) is not None)
check("rejects bad refundTo",
      bad_body(lambda b: b.update(refundTo="nope")) is not None)
check("accepts valid body", bad_body(lambda b: None) is None)

# canonical bytes exclude payerSignature and are deterministic
b1 = {"x402Version": 2, "payerSignature": "0xabc", "z": 1, "a": 2}
b2 = {"a": 2, "z": 1, "x402Version": 2, "payerSignature": "0xdef"}
check("canonical bytes deterministic + exclude sig",
      R.canonical_refund_bytes(b1) == R.canonical_refund_bytes(b2)
      and b"payerSignature" not in R.canonical_refund_bytes(b1))

# --------------------------------------------------------------------------
# 9. broadcast stub refuses outside test mode
# --------------------------------------------------------------------------
old = os.environ.pop("X402_REFUND_BROADCAST", None)
try:
    R.broadcast_refund_tx(NET, PAYER, 1, USDC)
    check("broadcast stub refuses when disabled", False)
except RuntimeError as e:
    check("broadcast stub refuses when disabled", "deploy-time" in str(e))
finally:
    if old is not None:
        os.environ["X402_REFUND_BROADCAST"] = old

# --------------------------------------------------------------------------
# 10. 402 advertisement carries the refund extension
# --------------------------------------------------------------------------
sys.path.insert(0, "/home/hatch/workspace/rider-x402")
os.environ.setdefault("X402_PAY_TO", PAY_TO)
import server as S
req402 = S.payment_requirements("ping", "ping", "rider-x402.fly.dev")
ext = req402.get("extensions", {}).get("refund", {})
check("402 advertises extensions.refund", bool(ext.get("info")))
check("402 refund endpoint", ext["info"]["refundEndpoint"] ==
      "https://rider-x402.fly.dev/x402/refund", ext["info"].get("refundEndpoint"))
check("402 refund window 24h", ext["info"]["windowSeconds"] == 86400)
check("402 refund partials on", ext["info"]["partialRefunds"] is True)

# --------------------------------------------------------------------------
# 11. state persistence roundtrip (restarts can't double-pay)
# --------------------------------------------------------------------------
import tempfile
tmpd = tempfile.mkdtemp()
sp = os.path.join(tmpd, "state.json")
S.STATE_PATH = sp
st = S.load_state()
st["refund_totals"][NET + ":" + TXH] = 10000
st["refund_idem"]["some-key"] = {"status": "executed"}
S.save_state(st)
st2 = S.load_state()
check("state roundtrips refund_totals",
      st2["refund_totals"][NET + ":" + TXH] == 10000)
check("state roundtrips refund_idem",
      st2["refund_idem"]["some-key"]["status"] == "executed")
check("state keeps used_tx", isinstance(st2["used_tx"], list))

# old-format state (used_tx only) still loads
with open(sp, "w") as f:
    json.dump({"used_tx": ["a"]}, f)
st3 = S.load_state()
check("legacy state loads", st3["used_tx"] == ["a"]
      and st3["refund_totals"] == {} and st3["refund_idem"] == {})

# --------------------------------------------------------------------------
# 12. split reserve/finalize/release (crash-safe server path)
# --------------------------------------------------------------------------
c = ctx_for(payments())
req = req_for(amount=10000, idem="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
ticket = R.reserve_refund(req, c)
check("reserve returns ticket (not replay)", "replay" not in ticket)
check("reserve debits totals",
      c["state"]["refund_totals"][NET + ":" + TXH] == 10000)
check("reserve caches broadcasting marker",
      c["state"]["refund_idem"][ticket["idem"]]["status"] == "broadcasting")
# a replayed key during broadcast returns the marker, no second debit
again = R.reserve_refund(req, c)
check("replay during broadcast returns marker",
      again["replay"]["status"] == "broadcasting")
check("no double debit on replay",
      c["state"]["refund_totals"][NET + ":" + TXH] == 10000)
resp = R.finalize_refund(ticket, c, "0x" + "cc" * 32)
check("finalize executes", resp["status"] == "executed"
      and resp["refundTxHash"] == "0x" + "cc" * 32)
check("finalize replaces marker",
      c["state"]["refund_idem"][ticket["idem"]]["status"] == "executed")

# broadcast failure -> release rolls back, key freed for retry
c = ctx_for(payments())
req = req_for(amount=10000, idem="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
ticket = R.reserve_refund(req, c)
R.release_refund(ticket, c)
check("release rolls back totals",
      c["state"]["refund_totals"].get(NET + ":" + TXH, 0) == 0)
check("release frees idempotency key", ticket["idem"] not in
      c["state"]["refund_idem"])
# retry with the same key works after release
ticket2 = R.reserve_refund(req, c)
check("retry after release reserves again", "replay" not in ticket2)
R.finalize_refund(ticket2, c, "0x" + "dd" * 32)
check("retry after release finalizes",
      c["state"]["refund_totals"][NET + ":" + TXH] == 10000)

# one-shot process_refund rolls back when broadcast raises
def boom(n, t, u, a):
    raise RuntimeError("boom")
c = ctx_for(payments(), broadcast=boom)
try:
    R.process_refund(req_for(amount=5000,
                             idem="cccccccc-cccc-cccc-cccc-cccccccccccc"), c)
    check("one-shot re-raises broadcast failure", False)
except RuntimeError:
    check("one-shot re-raises broadcast failure", True)
check("one-shot failure leaves no debit",
      c["state"]["refund_totals"].get(NET + ":" + TXH, 0) == 0)
check("one-shot failure leaves no cache entry",
      "cccccccc-cccc-cccc-cccc-cccccccccccc" not in c["state"]["refund_idem"])

print()
print("PASS %d  FAIL %d" % (len(PASS), len(FAIL)))
if FAIL:
    print("failures:", FAIL)
    sys.exit(1)
