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
