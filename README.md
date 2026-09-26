# rider-x402

x402 pay-per-call HTTP service for Agent Rider. Live at https://rider-x402.fly.dev

Unpaid POSTs return 402 with payment requirements; paid callers send `X-PAYMENT`,
verified on-chain (Base USDC), replay-protected.

Products: ping (1c), info/seats (2c), decompress/check (10c), compress (25c),
awareness/scan (10c).
