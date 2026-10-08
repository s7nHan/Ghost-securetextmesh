# Security Model

## Security goals

GHOST is designed to provide a security-first message flow with controls intended to protect confidentiality, integrity, authenticity, replay resistance, and controlled resource use.

## Publicly described controls

- AES-256-GCM authenticated encryption
- ML-DSA digital signatures
- Signature and message verification
- Nonce / replay protection
- Threshold secret sharing
- Secure fragmentation / reassembly controls
- Proof-of-Work based validation controls
- TTL / timeout controls
- Rate / resource controls
- Key lifecycle handling

## RAM-first principle

The system is designed to minimize persistent message material and to process the operational message lifecycle primarily in memory.

RAM-first does not mean that every operating-system, runtime, crash, swap, logging, telemetry, or infrastructure configuration automatically provides zero persistence. Deployment security must account for the full host environment.

## Security claim discipline

This repository distinguishes between:

- **implemented controls**;
- **internally validated behavior**;
- **independently certified behavior**.

Only the first two are currently represented in this public showcase unless explicit third-party evidence is added later.
