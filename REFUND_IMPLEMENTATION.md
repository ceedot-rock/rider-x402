# x402 `refund` extension — reference implementation notes

**Status:** implemented, 62/62 tests green (`test_refund.py`), existing
payment suite untouched (8/8 green). **Not deployed** — no Fly deploy was
done; the live `rider-x402` app is unchanged. Broadcast is stubbed: it
refuses unless `X402_REFUND_BROADCAST=test` (fake deterministic hashes) —
no real money can move.

Spec: `specs/extensions/refund.md` on branch `refund-extension` of the
ceedot-rock/x402 fork (filed upstream as x402-foundation/x402#3640).

## Files

- `refund.py` — the extension: request parsing/validation, payer-signature
  verification (EIP-191 personal_sign over canonical JSON of the wire
  fields), on-chain settlement lookup (`eth_getTransactionReceipt` +
  `eth_getBlockByNumber`, Transfer-log matching), the refund pipeline,
  signed refund receipts, broadcast stub.
- `test_refund.py` — 62 tests, zero network (fake RPC, test-mode broadcast).
- `server.py` — HTTP wiring only: `POST /x402/refund`, `GET
  /x402/refund/{idempotencyKey}`, `extensions.refund` advertised on every
  402, OpenAPI entries. Existing payment endpoints untouched.

## Key design decisions (beyond the spec)

1. **Payer binding is signature-only.** The request's `payerSignature` must
   recover to the address that sent the settled USDC transfer. No API keys,
   no sessions.
2. **Two-phase money-out** (`reserve_refund` → persist → broadcast →
   `finalize_refund` / `release_refund`). The reservation (totals debited +
   idempotency cache marked `"broadcasting"`) is saved to disk BEFORE any
   broadcast, so a crash between broadcast and finalize can never cause a
   second transfer on retry — the retried key returns the cached marker and
   the client polls `GET /x402/refund/{key}`. Broadcast failure rolls the
   reservation back and frees the key for retry.
3. **Denials are cached under the idempotency key** (so a repeated key
   returns the original response), EXCEPT `unknown_payment`, which is
   transient (tx may not be mined yet) and stays retryable.
4. **Totals are the backstop.** `refund_totals[network:txhash]` accumulates
   every executed refund; the pipeline refuses anything that would exceed
   settled-minus-refunded, even across server restarts (state persists in
   `state.json`, legacy format still loads).
5. **Window fail-closed.** If the node returns no block timestamp, the
   payment is treated as outside the refund window, not forever-valid.
6. **Canonical signing bytes** exclude `payerSignature` and the derived
   `amount_units`; clients sign the wire fields as canonical JSON.
7. **Production broadcaster requirements** (for whoever wires it later):
   must be idempotent — embed the idempotency key in tx calldata or derive
   a deterministic nonce from it — because a crash-retry may re-issue the
   broadcast call after the first tx already landed.

## Test coverage (all in test_refund.py)

- payer-signature rejection: wrong signer → `not_payer`; amount tampered
  post-sign → `not_payer`
- double-refund: full refund then second → `already_refunded`; totals
  unchanged
- idempotency: same key replay → byte-identical cached response, exactly
  one broadcast, totals debited once; denied keys return cached denials
- window: older than 24h → `outside_window`; exactly at edge accepted
- partials: two partials sum to settled; over-remainder →
  `amount_exceeds_settled`; policy can disable partials
- unknown payment: missing tx, reverted tx, no Transfer to pay_to,
  unsupported network → `unknown_payment` (not cached)
- request validation: 12 malformed-body cases → descriptive errors
- broadcast stub refuses when `X402_REFUND_BROADCAST` is unset
- 402 advertisement carries `extensions.refund` with endpoint/window/terms
- state.json roundtrip incl. legacy format
- split path: reserve debits + marks broadcasting; replay during
  broadcast is safe; finalize executes; release rolls back and frees the
  key; one-shot failure leaves no debit

## Not done (deliberate)

- No Fly deploy of the new code (per task limits).
- No production broadcaster — wiring it needs Corey's explicit plan
  approval before any real money moves.
- Solana: refund verification is EVM-only for now; the 402 advertises the
  extension on all rails but `refund.py` only resolves EVM networks.
