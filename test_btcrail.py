"""Tests for the Bitcoin rail: address handling, signed messages, pricing,
X-PAYMENT parsing, and the full verify path (synthetic tx + live API parse)."""
import base64
import hashlib
import json
import os
import sys

os.environ["X402_PAY_TO"] = "0x64E31E05583F250644b76d0FFe12e129ea4DeeCe"
os.environ["X402_PAY_TO_BTC"] = "bc1q3c4n9nw3pmfafjg8kh4flkyve7ucgchv3lh9sf"
os.environ["X402_RPC_URLS"] = "https://1rpc.io/base"
sys.path.insert(0, "/home/hatch/workspace/rider-x402")

import ethsig
import btcrail as b
import server

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("PASS", name)
    else:
        FAIL += 1
        print("FAIL", name)


# --- address validation ---
check("corey bc1q valid", b.is_valid_btc_address("bc1q3c4n9nw3pmfafjg8kh4flkyve7ucgchv3lh9sf"))
check("p2pkh valid", b.is_valid_btc_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
check("p2sh valid", b.is_valid_btc_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"))
check("garbage rejected", not b.is_valid_btc_address("bc1qzzzz"))
check("eth addr rejected", not b.is_valid_btc_address("0x64E31E05583F250644b76d0FFe12e129ea4DeeCe"))
check("testnet rejected", not b.is_valid_btc_address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))

# --- bech32 roundtrip ---
dec = b.bech32_decode("bc1q3c4n9nw3pmfafjg8kh4flkyve7ucgchv3lh9sf")
reenc = b.bech32_encode(dec[0], dec[1], dec[2])
check("bech32 roundtrip", reenc == "bc1q3c4n9nw3pmfafjg8kh4flkyve7ucgchv3lh9sf")

# --- base58check roundtrip ---
p = b.b58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
check("b58 genesis payload", p == bytes.fromhex("0062e907b15cbf27d5425399ebf6f0fb50ebb88f18"))
check("b58 roundtrip", b.b58check_encode(p) == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

# --- sign/verify roundtrip ---
priv = hashlib.sha256(b"btc rail unit test").digest()
pt = ethsig._point_mul(int.from_bytes(priv, "big"))
addr_wpkh = b.point_to_p2wpkh(pt)
addr_pkh = b.point_to_p2pkh(pt)
msg = b"rider-x402 payment proof\ntxHash: deadbeef\nresource: https://x/"
sig = b.sign_btc_message(msg, priv)
check("sign/verify p2wpkh", b.verify_btc_message(msg, sig, addr_wpkh))
check("sign/verify p2pkh", b.verify_btc_message(msg, sig, addr_pkh))
check("wrong addr rejected", not b.verify_btc_message(msg, sig, "bc1q3c4n9nw3pmfafjg8kh4flkyve7ucgchv3lh9sf"))
check("tampered msg rejected", not b.verify_btc_message(b"tampered", sig, addr_wpkh))
check("bad sig rejected", not b.verify_btc_message(msg, "AAAA", addr_wpkh))

# --- pricing ---
price = b.btc_usd_price()
check("live btc price sane", 1000 < price < 1000000)
sats = b.sats_for_cents(2, price)
check("2c sats sane", 1 <= sats <= 100000)
check("sats round up", b.sats_for_cents(2, 100000.0) == 20)  # 2*1e8/(100*1e5)=20
check("sats ceil", b.sats_for_cents(1, 86358.0) >= 1)

# --- live API parse of a real confirmed tx ---
tip_hash = b._btc_get_text("/blocks/tip/hash")
txids = b._btc_get("/block/%s/txids" % tip_hash)
rtx = b.fetch_btc_tx(txids[1])
check("real tx confirmed", bool((rtx.get("status") or {}).get("confirmed")))
check("real tx has vouts", len(rtx.get("vout") or []) > 0)
check("real tx vin prevouts", bool(((rtx.get("vin") or [{}])[0].get("prevout") or {}).get("scriptpubkey_address")))

# --- full verify path (synthetic) ---
payto = server.PAY_TO_BTC
fake_tx = {
    "txid": "bb" * 32,
    "status": {"confirmed": True, "block_height": 800000},
    "vout": [{"scriptpubkey_address": payto, "value": 100}],
    "vin": [{"prevout": {"scriptpubkey_address": addr_wpkh, "value": 1000}}],
}
b.fetch_btc_tx = lambda h: fake_tx
resource = "https://rider-x402.fly.dev/api/x402/cuni/seats"
bsig = b.sign_btc_message(ethsig.binding_message("bb" * 32, resource), priv)
ok, info = server._verify_bitcoin("bb" * 32, 24, set(), bsig, resource)
check("verify success", ok and info.get("paid_units") == 100)
used = set()
server._verify_bitcoin("bb" * 32, 24, used, bsig, resource)
ok, info = server._verify_bitcoin("bb" * 32, 24, used, bsig, resource)
check("replay blocked", not ok)
ok, info = server._verify_bitcoin("bb" * 32, 500, set(), bsig, resource)
check("underpaid caught", not ok and "underpaid" in info.get("reason", ""))
ok, info = server._verify_bitcoin("bb" * 32, 24, set(), bsig, "https://evil/")
check("resource binding enforced", not ok)
fake_tx["status"] = {"confirmed": False}
ok, info = server._verify_bitcoin("bb" * 32, 24, set(), bsig, resource)
check("unconfirmed refused", not ok)
fake_tx["status"] = {"confirmed": True, "block_height": 800000}
ok, info = server._verify_bitcoin("nothex", 24, set(), bsig, resource)
check("bad txid rejected", not ok)
ok, info = server._verify_bitcoin("bb" * 32, 24, set(), None, resource)
check("missing payerSig refused", not ok)

# --- X-PAYMENT parsing ---
payload = {"x402Version": 2, "scheme": "txHash", "network": server.BITCOIN_NETWORK,
           "payload": {"txid": "bb" * 32, "payerSig": "QUJD"}}
h = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
proof, net, psig, err = server.parse_x_payment(h)
check("x-payment btc parses", err is None and proof == "bb" * 32 and net == server.BITCOIN_NETWORK)
payload["payload"] = {}
h = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
check("x-payment missing txid errors", server.parse_x_payment(h)[3] is not None)

# --- challenge advertises btc ---
req = server.payment_requirements("cuni", "seats", "rider-x402.fly.dev")
btc_acc = [a for a in req["accepts"] if a["network"] == server.BITCOIN_NETWORK]
check("challenge has btc rail", len(btc_acc) == 1)
check("btc payTo corey", btc_acc and btc_acc[0]["payTo"] == "bc1q3c4n9nw3pmfafjg8kh4flkyve7ucgchv3lh9sf")
check("btc amount sats", btc_acc and btc_acc[0]["amount"].isdigit() and int(btc_acc[0]["amount"]) >= 1)

print()
print("PASS %d  FAIL %d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
