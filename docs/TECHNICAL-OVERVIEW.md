# Technical Overview

GHOST Secure Text Mesh is a Rust-based secure text communication system designed around resilient multi-node communication and a security-first message lifecycle.

## Implementation foundation

The private production implementation is written in **Rust**. Publicly described implementation components include:

- **Tokio** for asynchronous runtime, networking and concurrency orchestration;
- **ML-DSA** for post-quantum digital-signature workflows;
- **ML-KEM** for post-quantum key-establishment / encapsulation workflows;
- **AES-256-GCM** for authenticated encryption;
- **Shamir Secret Sharing** for threshold secret-sharing workflows.

The repository also contains a small non-production Rust lifecycle example under `examples/rust-showcase/`. It demonstrates only safe public concepts and does not expose production cryptographic or protocol code.

## Design objectives

GHOST is structured around four primary engineering objectives:

1. Resist malformed, tampered, replayed, or otherwise invalid message traffic.
2. Maintain reliable cryptographic message processing.
3. Sustain useful multi-node message behavior under disrupted connectivity.
4. Minimize persistent message data through RAM-first processing.

## Networking and resilience

Publicly documented networking capabilities include:

- Peer-to-peer communication
- Mesh-oriented multi-node operation
- Delay / disruption-tolerant delivery concepts
- Multi-node end-to-end transfer
- TTL / timeout controls
- Rate and resource controls
- Firewall / lockdown controls where configured

## Cryptography and message integrity

The current system design includes:

- ML-DSA digital signatures
- ML-KEM key-establishment / encapsulation workflows
- AES-256-GCM authenticated encryption
- Shamir threshold secret sharing
- Message fragmentation and reassembly
- Signature verification
- Nonce and replay protection
- Proof-of-Work based validation controls
- Key lifecycle handling

## Message lifecycle

The system is designed around a RAM-first flow:

```text
write → protect → fragment → send → receive → verify → reassemble → read → respond → delete
```

The public showcase intentionally omits implementation details that could expose security-sensitive internals.
