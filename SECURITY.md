# Security Policy

Rider x402 moves real money. A bug that lets a payment verify against the
wrong transaction, lets a refund execute twice, lets a 402 gate be bypassed,
or diverts a payout away from the configured wallet is a security issue, not
a normal bug.

## Reporting a vulnerability

Please do not open a public issue for security problems.

- Email: corey@slidphilabs.com with the subject line `Rider x402 security`
- Or use GitHub's private vulnerability reporting on this repository
  (Security tab, "Report a vulnerability")

Include the affected endpoint or module, the rail involved, steps or inputs
to reproduce, and what you expected versus what happened.

You can expect an acknowledgement within 3 business days. We will keep you
updated while we investigate and credit you in the changelog unless you
prefer to stay anonymous.

## In scope

- Payment verification: a transaction that verifies without a real on-chain
  transfer to the configured pay-to
- Refund double-spend: an idempotency key that executes twice
- Gate bypass: any path to a paid product without a verified payment
- Pay-to confusion: a payment credited to or refunded to the wrong address
- Signature or replay weaknesses in the `txHash` scheme handling
- The x402 refund extension and the Bitcoin rail

## Out of scope

- Operator deployments we do not run
- Social engineering, spam, or denial-of-service against hosted demos
