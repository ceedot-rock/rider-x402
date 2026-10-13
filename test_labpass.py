#!/usr/bin/env python3
"""Tests for the lab free-use pass (LAB_WALLETS).

The lab's own wallets get $0 quotes but still run the full x402 proof
flow: real mined tx + payerSig bound to the allowlisted address. Chain IO
is injected via a fake RPC — zero network.

Covers:
  - parse_lab_wallets: valid kept (lowercased), malformed ignored, no crash
  - lab_payer_claim: X-PAYER header handling
  - payment_requirements: $0 402 keeps valid x402 fields; default prices
    unchanged (2c/10c/25c for pcc)
  - _verify_evm: allowlisted payer + 0-value transfer -> ok + lab_free;
    non-allowlisted payer + 0-value -> underpaid; unset env -> unchanged
    (underpaid); replay still enforced for lab txs
  - spoofed X-PAYER claim cannot complete without the allowlisted key

Run:  python3 test_labpass.py
"""
import os
import secrets
import sys

# Env must be set before importing server (module reads env at import).
os.environ.setdefault("X402_PAY_TO", "0x" + "11" * 20)
os.environ.setdefault("X402_RPC_URLS", "https://example.invalid")
sys.path.insert(0, "/home/hatch/workspace/rider-x402")

import ethsig
import server as S

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("  ok " if cond else "  FAIL ") + name
          + (" -- " + str(detail)[:200] if detail and not cond else ""))


def fresh_key():
    priv = secrets.token_hex(32)
    addr = "0x" + ethsig.privkey_to_address(priv).hex()
    return priv, addr


def pad_topic(addr):
    return "0x" + "00" * 12 + addr[2:].lower()


def fake_receipt(payer, pay_to, usdc, value_units=0, tx_from=None):
    return {
        "status": "0x1",
        "from": tx_from or payer,
        "logs": [{
            "address": usdc,
            "topics": [S.TRANSFER_TOPIC, pad_topic(payer), pad_topic(pay_to)],
            "data": "0x" + ("%064x" % value_units),
        }],
    }


def fake_rpc(receipt):
    def call(method, params):
        assert method == "eth_getTransactionReceipt", method
        return {"result": receipt}
    return call


TXH = "0x" + "ab" * 32
RESOURCE = "https://rider-x402.fly.dev/api/x402/pcc/compress"
NET = S.NETWORK_CAIP2
RAIL = S.EVM_RAILS[NET]
MIN25 = 25 * S.UNITS_PER_CENT  # normal pcc/compress price in base units

print("== parse_lab_wallets ==")
check("empty string -> empty set", S.parse_lab_wallets("") == frozenset())
check("None -> empty set", S.parse_lab_wallets(None) == frozenset())
w = S.parse_lab_wallets("0x" + "AA" * 20 + ", 0x" + "bb" * 20)
check("two valid kept, lowercased",
      w == frozenset({"0x" + "aa" * 20, "0x" + "bb" * 20}), w)
w = S.parse_lab_wallets("not-an-address, 0x123, 0x" + "zz" * 20
                        + ", , 0x" + "CC" * 20 + ", 0X" + "dd" * 20)
check("malformed ignored safely, no crash",
      w == frozenset({"0x" + "cc" * 20}), w)
check("0X prefix rejected (must be 0x)",
      S.parse_lab_wallets("0X" + "dd" * 20) == frozenset())

print("== lab_payer_claim ==")
S.LAB_WALLETS = frozenset({"0x" + "aa" * 20})
check("allowlisted X-PAYER claimed (mixed case ok)",
      S.lab_payer_claim({"X-PAYER": "0x" + "Aa" * 20}) == "0x" + "aa" * 20)
check("non-allowlisted X-PAYER -> None",
      S.lab_payer_claim({"X-PAYER": "0x" + "bb" * 20}) is None)
check("malformed X-PAYER -> None",
      S.lab_payer_claim({"X-PAYER": "garbage"}) is None)
check("missing X-PAYER -> None", S.lab_payer_claim({}) is None)
S.LAB_WALLETS = frozenset()
check("env unset: header ignored entirely",
      S.lab_payer_claim({"X-PAYER": "0x" + "aa" * 20}) is None)

print("== payment_requirements ==")
S.PAY_TO = "0x" + "11" * 20
body = S.payment_requirements("pcc", "compress", "rider-x402.fly.dev",
                              lab_free=True)
acc = body["accepts"][0]
check("$0 quote: x402Version 2", body["x402Version"] == 2)
check("$0 quote: scheme txHash", acc["scheme"] == "txHash")
check("$0 quote: network eip155:8453", acc["network"] == "eip155:8453")
check("$0 quote: amount '0'", acc["amount"] == "0")
check("$0 quote: payTo set", acc["payTo"] == S.PAY_TO)
check("$0 quote: asset is USDC", acc["asset"] == S.USDC_BASE)
check("$0 quote: maxTimeoutSeconds 300", acc["maxTimeoutSeconds"] == 300)
check("$0 quote: labFree marker", body.get("labFree") is True)
check("$0 quote: howto says >= 0c",
      ">= 0" in acc["extra"]["howto"])
hdr = S.payment_required_header("pcc", "compress", "rider-x402.fly.dev",
                                lab_free=True)
import base64 as _b64
import json as _json
dec = _json.loads(_b64.urlsafe_b64decode(hdr + "=" * (-len(hdr) % 4)))
check("$0 quote: PAYMENT-REQUIRED header decodes with amount 0",
      dec["accepts"][0]["amount"] == "0" and dec.get("labFree") is True)

for prod_op, cents in [(("pcc", "compress"), 25), (("pcc", "decompress"), 10),
                       (("pcc", "info"), 2)]:
    b = S.payment_requirements(prod_op[0], prod_op[1],
                               "rider-x402.fly.dev")
    want = str(cents * S.UNITS_PER_CENT)
    check("default price %s/%s = %dc (%s units)" % (prod_op[0], prod_op[1],
                                                   cents, want),
          b["accepts"][0]["amount"] == want and "labFree" not in b,
          b["accepts"][0]["amount"])

print("== _verify_evm lab pass ==")
priv, lab_addr = fresh_key()
S.LAB_WALLETS = frozenset({lab_addr.lower()})
sig = ethsig.sign_personal(ethsig.binding_message(TXH, RESOURCE), priv)
rcpt = fake_receipt(lab_addr, S.PAY_TO, S.USDC_BASE, value_units=0)
ok, info = S._verify_evm(TXH, NET, RAIL, MIN25, set(),
                         rpc=fake_rpc(rcpt), payer_sig=sig,
                         resource=RESOURCE)
check("allowlisted payer, 0-value transfer -> ok",
      ok, info)
check("allowlisted payer -> lab_free marked",
      ok and info.get("lab_free") is True, info)
check("allowlisted payer -> payer recovered",
      ok and info.get("payer") == lab_addr.lower(), info)
check("allowlisted payer -> paid_units 0",
      ok and info.get("paid_units") == 0, info)

print("== _verify_evm non-lab / unset env ==")
priv2, other_addr = fresh_key()
sig2 = ethsig.sign_personal(ethsig.binding_message(TXH, RESOURCE), priv2)
rcpt2 = fake_receipt(other_addr, S.PAY_TO, S.USDC_BASE, value_units=0)
ok2, info2 = S._verify_evm(TXH, NET, RAIL, MIN25, set(),
                           rpc=fake_rpc(rcpt2), payer_sig=sig2,
                           resource=RESOURCE)
check("non-allowlisted payer, 0-value transfer -> underpaid",
      (not ok2) and info2.get("reason", "").startswith("underpaid"), info2)
check("non-lab info has no lab_free key",
      "lab_free" not in info2, info2)

S.LAB_WALLETS = frozenset()  # env-unset behavior
ok3, info3 = S._verify_evm(TXH, NET, RAIL, MIN25, set(),
                           rpc=fake_rpc(rcpt), payer_sig=sig,
                           resource=RESOURCE)
check("env unset: lab 0-value transfer -> underpaid (unchanged)",
      (not ok3) and info3.get("reason", "").startswith("underpaid"), info3)

print("== _verify_evm normal payment still works with env set ==")
S.LAB_WALLETS = frozenset({lab_addr.lower()})
priv3, payer3 = fresh_key()
sig3 = ethsig.sign_personal(ethsig.binding_message(TXH, RESOURCE), priv3)
rcpt3 = fake_receipt(payer3, S.PAY_TO, S.USDC_BASE, value_units=MIN25)
ok4, info4 = S._verify_evm(TXH, NET, RAIL, MIN25, set(),
                           rpc=fake_rpc(rcpt3), payer_sig=sig3,
                           resource=RESOURCE)
check("normal 25c payment still verifies",
      ok4 and info4.get("paid_units") == MIN25
      and "lab_free" not in info4, info4)

print("== replay still enforced for lab txs ==")
used = set()
ok5, info5 = S._verify_evm(TXH, NET, RAIL, MIN25, used,
                           rpc=fake_rpc(rcpt), payer_sig=sig,
                           resource=RESOURCE)
ok6, info6 = S._verify_evm(TXH, NET, RAIL, MIN25, used,
                           rpc=fake_rpc(rcpt), payer_sig=sig,
                           resource=RESOURCE)
check("lab tx accepted once, replay rejected",
      ok5 and (not ok6) and "replay" in info6.get("reason", ""), info6)

print("== spoofed X-PAYER cannot complete ==")
# Attacker claims the lab address in X-PAYER but signs/pays with their own.
S.LAB_WALLETS = frozenset({lab_addr.lower()})
claimed = S.lab_payer_claim({"X-PAYER": lab_addr})
check("spoofed claim gets $0 quote", claimed == lab_addr.lower())
ok7, info7 = S._verify_evm(TXH, NET, RAIL, MIN25, set(),
                           rpc=fake_rpc(rcpt2), payer_sig=sig2,
                           resource=RESOURCE)
check("spoofed claim, attacker key -> underpaid, no lab_free",
      (not ok7) and "lab_free" not in info7, info7)

print()
print("PASS %d  FAIL %d" % (len(PASS), len(FAIL)))
sys.exit(1 if FAIL else 0)
