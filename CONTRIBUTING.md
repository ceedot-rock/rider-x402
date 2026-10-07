# Contributing to Rider x402

Thanks for helping make agent payments simple.

## Ground rules

- All money math is in integer units (USDC microunits, cents, sats). No
  floats on any payment path, ever.
- Paid endpoints must keep the 402-first contract: an unpaid request answers
  with `x402Version` payment requirements, never a generic error.
- A refund denial is a result, not something to work around — the extension
  is idempotent by key, and a crashed reservation must never double-spend.

## Quick checks

```sh
python3 test_refund.py     # refund extension: 62 cases
python3 test_btcrail.py    # Bitcoin rail: 33 cases
```

CI runs these plus an API smoke test (boot `server.py`, probe `/health`,
`/`, `/openapi.json`, and one unpaid 402 POST) on every pull request.

## Running the server locally

```sh
X402_PAY_TO=0x<lab-wallet> X402_RPC_URLS=http://127.0.0.1:8545 \
python3 server.py
```

Never commit real wallet addresses, pay-tos, RPC URLs, or keys — pass them
through the environment. `.env` is gitignored.

## Adding or changing an endpoint

1. Add the product/op and price to `PRODUCTS` in `server.py`.
2. Add or extend cases in the matching test file (`test_*.py`).
3. Run both test files — they must print `FAIL 0`.
4. Open a pull request using the template.

## Licensing

Rider x402 is dual-licensed (AGPL-3.0-or-later or the Slid Phi Labs
Commercial License). By contributing you agree your contribution may be
distributed under both.
