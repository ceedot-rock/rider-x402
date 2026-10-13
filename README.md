# rider-x402

[![Audited checks](https://github.com/ceedot-rock/rider-x402/actions/workflows/audited-checks.yml/badge.svg)](https://github.com/ceedot-rock/rider-x402/actions/workflows/audited-checks.yml)
[![License: AGPL-3.0-or-later / Commercial](https://img.shields.io/badge/license-AGPL--3.0--or--later%20%2F%20commercial-blue.svg)](LICENSE)

## What x402 is

x402 is the open payment protocol the lab's paid endpoints speak — and the way AI agents pay for things. It works like a vending machine for the web: you ask for something, the machine tells you the price, you pay, it vends.

Here is how it goes. An agent makes a request without paying. Instead of an error, the server answers with HTTP 402 — "payment required" — plus exact instructions: what it accepts, how much, where to send it. The agent pays on-chain in USDC, then retries the same request with proof of payment attached. The server verifies the payment and delivers.

Humans still pay the normal way, with Stripe or an invoice — same products, same prices. x402 exists so an agent can complete a purchase without a browser, a checkout page, or a human in the loop. No account, no API key signup: the payment is the credential.

Every paid endpoint in the lab speaks the same protocol, so once an agent learns to pay one, it can pay them all.

x402 pay-per-call HTTP service for Agent Rider. Live at https://rider-x402.fly.dev

Unpaid POSTs return 402 with payment requirements; paid callers send `X-PAYMENT`,
verified on-chain (Base USDC), replay-protected.

Products: ping (1c); pcc/slidx compress (25c), decompress (10c), info (2c);
cuni check (10c), seats (2c), emit (25c), ingest (25c);
trustream pack/unpack (10c), info (2c); awareness/scan (10c).

### Lab free-use pass

The lab's own wallets don't pay per call for internal use (benchmarking,
demos, dogfooding). Set `LAB_WALLETS` to a comma-separated list of the
lab's paying addresses:

```
fly secrets set LAB_WALLETS=0xabc...,0xdef... -a rider-x402
```

Allowlisted callers send `X-PAYER: <their address>` and get a **$0** 402
quote — but the x402 flow still runs end to end: a real (0-value) USDC
transfer to the lab wallet plus a `payerSig` from the allowlisted address,
verified on-chain exactly like a paid call. The claim in `X-PAYER` is never
trusted on its own — spoofing it only gets you a $0 quote you can't
complete without the lab's private key. Lab calls are logged with
`lab_free: true` and the recovered payer address, so volume monitoring
keeps working. With `LAB_WALLETS` unset, pricing is byte-identical to
before; malformed entries in the list are ignored.
