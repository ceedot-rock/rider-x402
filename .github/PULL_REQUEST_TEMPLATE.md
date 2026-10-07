## What changed

<!-- One or two sentences. -->

## Endpoints / modules touched

<!-- e.g. POST /api/x402/trustream/pack, refund.py, or "none" -->

## Checks

- [ ] `python3 test_refund.py` passes
- [ ] `python3 test_btcrail.py` passes
- [ ] Money math stays in integer units (cents / sats), no floats on any payment path
- [ ] No new secrets, keys, or wallet addresses committed
