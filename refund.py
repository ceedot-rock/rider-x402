#!/usr/bin/env python3
"""refund.py: reference implementation of the x402 `refund` extension.

Implements the wire format from specs/extensions/refund.md (x402-foundation):
servers advertise refund terms in PaymentRequired.extensions.refund, clients
POST a signed RefundRequest, the server verifies the original payment on-chain,
checks the payer signature, enforces window/idempotency/totals, executes the
refund from its own funds, and returns a signed refund receipt.

Signature profile (reference-implementation choice, documented):
  x402's Offer/Receipt extension uses EIP-712 or JWS. This server already
  binds payment proofs with EIP-191 personal_sign (see ethsig.binding_message),
  so the refund extension here uses the same profile: payerSignature is an
  EIP-191 personal_sign over the canonical refund-request bytes, and the
  refund receipt is an EIP-191 personal_sign by the server's refund signer
  key. Artifact shape ({format, payload, signature}) matches the Offer and
  Receipt extension; format is "eip191" instead of "eip712"/"jws".

Money safety:
  - Read-only chain access for verification (receipt + Transfer logs + block
    timestamp). No spending in this module's verify path.
  - Broadcast goes through `broadcast_refund_tx`, which REFUSES unless
    X402_REFUND_BROADCAST=test (deterministic fake hash for tests/demos).
    Production wiring (real signer + key management) is a deploy-time
    decision owned by Corey — this module never holds mainnet keys.
  - Per-payment refunded totals and idempotency-key responses persist in the
    server state file, so restarts cannot double-pay.

All chain IO is injected (rpc_call) so tests run with zero network.
"""

import hashlib
import json
import os
import re
import time

import ethsig

# --------------------------------------------------------------------------
# constants
# --------------------------------------------------------------------------

REFUND_WINDOW_SECONDS = 86400  # 24h, advertised in 402s
REFUND_REASONS = (
    "service_not_delivered",
    "service_defective",
    "duplicate_payment",
    "overcharge",
    "customer_request",
    "other",
)
REFUND_DENIALS = (
    "outside_window",
    "not_payer",
    "already_refunded",
    "amount_exceeds_settled",
    "policy_denied",
    "unknown_payment",
)
# Receipt EIP-712-style domain name for the refund receipt artifact; the
# signature itself is EIP-191 personal_sign (see module docstring).
REFUND_RECEIPT_DOMAIN = "x402 refund receipt"

_TXHASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class RefundError(Exception):
    """Caller-side problem with a machine-readable denial reason."""
    def __init__(self, denial, detail=""):
        super().__init__(detail or denial)
        self.denial = denial


# --------------------------------------------------------------------------
# 1. advertisement (goes into PaymentRequired.extensions)
# --------------------------------------------------------------------------

def refund_extension_info(host):
    """The `refund` extension object for 402 PaymentRequired responses."""
    return {
        "info": {
            "refundEndpoint": "https://%s/x402/refund" % host,
            "windowSeconds": REFUND_WINDOW_SECONDS,
            "partialRefunds": True,
            "policyUrl": "https://www.slidphilabs.com/refund-policy",
        },
        "schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "refundEndpoint": {"type": "string", "format": "uri"},
                "windowSeconds": {"type": "integer", "minimum": 0},
                "partialRefunds": {"type": "boolean"},
                "policyUrl": {"type": "string", "format": "uri"},
            },
            "required": ["refundEndpoint", "windowSeconds", "partialRefunds"],
        },
    }


# --------------------------------------------------------------------------
# 2. canonical bytes + payer signature
# --------------------------------------------------------------------------

def canonical_refund_bytes(req):
    """Canonical bytes the payer signs (EIP-191 personal_sign).

    The wire fields only (derived fields like amount_units and the
    signature itself are excluded), canonical JSON (sorted keys, no
    whitespace). Deterministic across implementations: the client signs
    this exact form and the server re-derives it after parsing.
    """
    body = {k: v for k, v in req.items()
            if k not in ("payerSignature", "amount_units")}
    return json.dumps(body, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def verify_payer_signature(req, payer_address):
    """True iff req["payerSignature"] is the payer's personal_sign over the
    canonical request bytes."""
    sig = req.get("payerSignature") or ""
    signer = ethsig.verify_personal_sign(canonical_refund_bytes(req), sig)
    if signer is None:
        return False
    return ("0x" + signer.hex()).lower() == (payer_address or "").lower()


# --------------------------------------------------------------------------
# 3. request parsing / validation (no chain IO)
# --------------------------------------------------------------------------

def parse_refund_request(body):
    """Validate the wire shape. Returns (req, error). req is normalized."""
    if not isinstance(body, dict):
        return None, "body must be a JSON object"
    req = dict(body)
    if req.get("x402Version") != 2:
        return None, "x402Version must be 2"
    pr = req.get("paymentReference")
    if not isinstance(pr, dict):
        return None, "paymentReference must be an object"
    txh = (pr.get("txHash") or "").strip()
    if not _TXHASH_RE.match(txh):
        return None, "paymentReference.txHash must be 0x + 64 hex"
    network = (pr.get("network") or "").strip()
    if not network:
        return None, "paymentReference.network is required"
    amount = req.get("amount")
    try:
        amount_units = int(str(amount).strip())
    except (ValueError, TypeError, AttributeError):
        return None, "amount must be an integer string of atomic units"
    if amount_units <= 0:
        return None, "amount must be positive"
    reason = req.get("reason")
    if reason not in REFUND_REASONS:
        return None, ("reason must be one of: %s" % ", ".join(REFUND_REASONS))
    refund_to = (req.get("refundTo") or "").strip()
    if refund_to and not _ADDR_RE.match(refund_to):
        return None, "refundTo must be a 0x address"
    idem = (req.get("idempotencyKey") or "").strip()
    if not _UUID_RE.match(idem):
        return None, "idempotencyKey must be a UUID"
    if not (req.get("payerSignature") or "").strip():
        return None, "payerSignature is required"
    req["paymentReference"] = {
        "txHash": txh.lower(),
        "network": network,
    }
    if pr.get("paymentId"):
        req["paymentReference"]["paymentId"] = pr.get("paymentId")
    req["amount_units"] = amount_units  # derived, NOT part of signed bytes
    req["refundTo"] = refund_to.lower() if refund_to else ""
    req["idempotencyKey"] = idem
    return req, None


# --------------------------------------------------------------------------
# 4. on-chain payment lookup (read-only)
# --------------------------------------------------------------------------

def lookup_settled_payment(rpc_call, network, tx_hash, pay_to, usdc_contract,
                           transfer_topic):
    """Resolve the settled payment from chain state.

    Returns (payment, error) where payment =
      {"payer": "0x..", "settled_units": int, "settled_ts": int}
    or raises RefundError("unknown_payment", ...).
    """
    try:
        resp = rpc_call("eth_getTransactionReceipt", [tx_hash])
    except Exception as e:  # noqa: BLE001 - clean denial, not a 500
        raise RefundError("unknown_payment",
                          "rpc unreachable while looking up payment: %s"
                          % str(e)[:100])
    receipt = resp.get("result") if isinstance(resp, dict) else None
    if not receipt:
        raise RefundError("unknown_payment", "tx not found / not mined yet")
    if receipt.get("status") not in ("0x1", 1):
        raise RefundError("unknown_payment", "tx reverted (status != ok)")
    # payer + settled amount from the USDC Transfer logs to pay_to
    pay_to_lc = pay_to.lower()
    senders = set()
    total = 0
    for log in receipt.get("logs", []) or []:
        if not isinstance(log, dict):
            continue
        if (log.get("address") or "").lower() != usdc_contract.lower():
            continue
        topics = log.get("topics", []) or []
        if len(topics) < 3 or (topics[0] or "").lower() != transfer_topic.lower():
            continue
        to_addr = "0x" + (topics[2] or "")[-40:]
        if to_addr.lower() != pay_to_lc:
            continue
        from_addr = "0x" + (topics[1] or "")[-40:]
        if _ADDR_RE.match(from_addr):
            senders.add(from_addr.lower())
        try:
            total += int(log.get("data", "0x0"), 16)
        except (ValueError, TypeError):
            continue
    if not senders:
        raise RefundError("unknown_payment",
                          "no USDC transfer to %s in tx logs" % pay_to)
    if len(senders) > 1:
        raise RefundError("unknown_payment",
                          "ambiguous payer: %d distinct token senders"
                          % len(senders))
    if total <= 0:
        raise RefundError("unknown_payment", "settled amount is zero")
    # settlement timestamp from the block
    block_num = receipt.get("blockNumber")
    try:
        bresp = rpc_call("eth_getBlockByNumber", [block_num, False])
        blk = bresp.get("result") if isinstance(bresp, dict) else None
        settled_ts = int(blk.get("timestamp"), 16) if blk else 0
    except Exception:  # noqa: BLE001 - timestamp optional-ish
        settled_ts = 0
    return {"payer": next(iter(senders)),
            "settled_units": total,
            "settled_ts": settled_ts}


# --------------------------------------------------------------------------
# 5. broadcast (STUB — see module docstring)
# --------------------------------------------------------------------------

def broadcast_refund_tx(network, to_address, amount_units, asset):
    """Send the refund on-chain from the server's own funds.

    **** STUB — NOT A REAL BROADCAST ****
    Real money movement needs the server's funded key, which this module
    deliberately never holds. Behavior:
      X402_REFUND_BROADCAST=test -> deterministic fake tx hash (tests/demos)
      anything else               -> RuntimeError (refuse loudly)
    Production wiring is a deploy-time decision owned by Corey.
    """
    if os.environ.get("X402_REFUND_BROADCAST", "disabled") == "test":
        seed = "|".join([network, to_address.lower(), str(amount_units),
                          asset.lower()])
        return "0x" + hashlib.sha256(
            ("refund-test:" + seed).encode()).hexdigest()
    raise RuntimeError(
        "refund broadcast not configured: set X402_REFUND_BROADCAST=test for "
        "dry runs; production needs the server's funded refund key, which is "
        "a deploy-time decision")


# --------------------------------------------------------------------------
# 6. signed refund receipt
# --------------------------------------------------------------------------

def sign_refund_receipt(payload, signer_key):
    """Sign the refund receipt artifact (EIP-191 personal_sign profile).

    Returns {"format": "eip191", "payload": payload, "signature": "0x..."}.
    """
    canonical = json.dumps(payload, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
    sig = ethsig.sign_personal(canonical, signer_key)
    return {"format": "eip191", "payload": payload, "signature": sig}


def verify_refund_receipt(artifact, signer_address):
    """True iff artifact.signature is signer_address's personal_sign over the
    canonical payload bytes."""
    if not isinstance(artifact, dict) or artifact.get("format") != "eip191":
        return False
    payload = artifact.get("payload")
    if not isinstance(payload, dict):
        return False
    canonical = json.dumps(payload, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
    signer = ethsig.verify_personal_sign(canonical,
                                         artifact.get("signature") or "")
    return (signer is not None
            and ("0x" + signer.hex()).lower() == signer_address.lower())


# --------------------------------------------------------------------------
# 7. the pipeline
# --------------------------------------------------------------------------

def _paykey(network, tx_hash):
    return "%s:%s" % (network, tx_hash.lower())


def process_refund(req, ctx):
    """One-shot refund: reserve -> broadcast -> finalize.

    Convenience wrapper for tests and simple integrators. The production
    server (server.py) uses the split reserve/finalize/release path so the
    reservation is persisted BEFORE any money moves; see the note on
    crash safety in reserve_refund.
    """
    ticket = reserve_refund(req, ctx)
    if "replay" in ticket:
        return ticket["replay"]
    try:
        refund_tx = ctx["broadcast"](ticket["network"], ticket["dest"],
                                     ticket["amount_units"], ticket["asset"])
    except Exception:
        release_refund(ticket, ctx)
        raise
    return finalize_refund(ticket, ctx, refund_tx)


def reserve_refund(req, ctx):
    """Verify everything and RESERVE the amount. Returns a ticket (plain
    data, safe to persist or pass across a save_state boundary).

    Crash safety: the caller MUST persist state (save_state) after reserve
    and BEFORE broadcasting. If the process dies after the broadcast but
    before finalize, the idempotency cache holds status "broadcasting" and
    the totals hold the reservation, so a retried key can never trigger a
    second transfer — the client polls GET /x402/refund/{key} until the
    status resolves. Production broadcasters MUST make the on-chain refund
    idempotent (e.g. embed the idempotency key in tx calldata or derive a
    deterministic nonce from it) so a retried broadcast after a crash is
    a no-op on chain.
    """
    state = ctx["state"]
    idem = req["idempotencyKey"]
    idem_cache = state.setdefault("refund_idem", {})

    # idempotency first: a repeated key returns the ORIGINAL response and
    # performs no new verification, accounting, or broadcast.
    if idem in idem_cache:
        return {"replay": dict(idem_cache[idem])}
    try:
        ticket = _verify_and_reserve(req, ctx)
    except RefundError as e:
        if e.denial != "unknown_payment":
            idem_cache[idem] = denial_response(req, e)
        raise
    # reservation: totals are debited NOW, before any money moves; the
    # cached "broadcasting" marker makes retries safe.
    totals = state.setdefault("refund_totals", {})
    key = ticket["paykey"]
    totals[key] = int(totals.get(key, 0)) + ticket["amount_units"]
    idem_cache[idem] = {"status": "broadcasting",
                        "amount": str(ticket["amount_units"]),
                        "idempotencyKey": idem,
                        "paymentTxHash": ticket["tx_hash"],
                        "network": ticket["network"]}
    if len(idem_cache) > 20000:
        for k in list(idem_cache)[:len(idem_cache) - 20000]:
            del idem_cache[k]
    return ticket


def release_refund(ticket, ctx):
    """Roll back a reservation (broadcast failed). The idempotency key is
    freed so the client may retry later with the same key."""
    if "replay" in ticket:
        return
    state = ctx["state"]
    totals = state.setdefault("refund_totals", {})
    key = ticket["paykey"]
    totals[key] = max(0, int(totals.get(key, 0)) - ticket["amount_units"])
    state.get("refund_idem", {}).pop(ticket["idem"], None)


def finalize_refund(ticket, ctx, refund_tx):
    """Broadcast succeeded: build the executed response (+ signed receipt)
    and replace the "broadcasting" cache entry. Returns the response."""
    if "replay" in ticket:
        return ticket["replay"]
    state = ctx["state"]
    idem_cache = state.setdefault("refund_idem", {})
    now = ctx.get("now", int(time.time()))
    payload = {
        "domain": REFUND_RECEIPT_DOMAIN,
        "network": ticket["network"],
        "paymentTxHash": ticket["tx_hash"],
        "refundTxHash": refund_tx,
        "payer": ticket["payer"],
        "refundTo": ticket["dest"],
        "asset": ticket["asset"],
        "amount": str(ticket["amount_units"]),
        "idempotencyKey": ticket["idem"],
        "reason": ticket["reason"],
        "executedAt": now,
    }
    signer_key = ctx.get("signer_key")
    receipt = (sign_refund_receipt(payload, signer_key)
               if signer_key else None)
    resp = {"status": "executed", "amount": str(ticket["amount_units"]),
            "refundTxHash": refund_tx}
    if receipt:
        resp["refundReceipt"] = receipt
        resp["refundSigner"] = ("0x" + ethsig.privkey_to_address(
            signer_key).hex())
    idem_cache[ticket["idem"]] = dict(resp)
    return resp


def _verify_and_reserve(req, ctx):
    pay_to = ctx["pay_to"]
    rails = ctx["rails"]
    network = req["paymentReference"]["network"]
    tx_hash = req["paymentReference"]["txHash"]
    amount = req["amount_units"]
    idem = req["idempotencyKey"]
    state = ctx["state"]
    now = ctx.get("now", int(time.time()))
    window = ctx.get("window_seconds", REFUND_WINDOW_SECONDS)
    totals = state.setdefault("refund_totals", {})

    rail = rails.get(network)
    if not rail:
        raise RefundError("unknown_payment", "unsupported network %r" % network)

    rpc = ctx.get("rpc_call")
    if rpc is None:
        raise RuntimeError("live RPC not wired in this context")

    payment = lookup_settled_payment(rpc, network, tx_hash, pay_to,
                                     rail["usdc"], ctx["transfer_topic"])
    payer = payment["payer"]
    settled = payment["settled_units"]

    # window enforcement (settled_ts==0 means the node gave no timestamp;
    # fail closed: treat as outside the window rather than forever-valid)
    if window > 0:
        if not payment["settled_ts"] or now - payment["settled_ts"] > window:
            raise RefundError("outside_window",
                              "payment settled outside the %ds refund window"
                              % window)

    # payer binding
    if not verify_payer_signature(req, payer):
        raise RefundError("not_payer",
                          "payerSignature does not recover to the paying "
                          "address %s" % payer)

    # per-request policy cap
    max_units = ctx.get("max_refund_units")
    if max_units and amount > max_units:
        raise RefundError("policy_denied",
                          "amount exceeds per-refund policy cap")

    # totals: never refund more than settled, across all refunds
    key = _paykey(network, tx_hash)
    already = int(totals.get(key, 0))
    if already >= settled:
        raise RefundError("already_refunded",
                          "payment already fully refunded")
    if already + amount > settled:
        raise RefundError("amount_exceeds_settled",
                          "requested %d + already-refunded %d exceeds "
                          "settled %d" % (amount, already, settled))
    if not ctx.get("partial_refunds", True) and already + amount != settled:
        raise RefundError("policy_denied", "partial refunds are disabled")

    # checks passed: return a plain-data ticket. No money moves here;
    # the caller reserves (reserve_refund), persists, then broadcasts.
    return {
        "network": network,
        "tx_hash": tx_hash,
        "paykey": key,
        "payer": payer,
        "dest": req["refundTo"] or payer,
        "amount_units": amount,
        "asset": rail["usdc"],
        "idem": idem,
        "reason": req["reason"],
    }


def denial_response(req, err):
    """RefundResponse for a denied request."""
    amount = req.get("amount_units") if isinstance(req, dict) else None
    return {"status": "denied",
            "amount": str(amount) if amount else str(
                req.get("amount") if isinstance(req, dict) else 0),
            "denialReason": err.denial,
            "denialDetail": str(err)}
