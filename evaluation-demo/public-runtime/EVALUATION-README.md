# GHOST Secure Text Mesh — Evaluation Demo v1.0

This is a limited, independently implemented evaluation demonstration.

## Linux x86_64

Extract the Linux ZIP and run:

    chmod +x ghost_eval_node
    ./ghost_eval_node

## Windows x86_64

Extract the Windows ZIP.

Open PowerShell inside the extracted folder and run:

    .\ghost_eval_node.exe

## What this demonstration performs

The executable creates three real libp2p QUIC nodes within
one local application process.

It demonstrates:

- Authenticated P2P/QUIC networking
- Signed Gossipsub messaging
- ML-KEM-768 key encapsulation
- ML-DSA-87 signatures
- AES-256-GCM encryption
- Shamir 3-of-5 secret reconstruction
- Encrypted RAM-based DTN queueing
- Receiver disconnect and reconnect
- Delayed encrypted message delivery
- Receiver-signed delivery acknowledgment
- Queue release after valid acknowledgment

The scenarios execute automatically using loopback networking.

## Important limitations

This is not the complete commercial GHOST production system.

It is a bounded, single-process, three-node live demonstration.
It does not provide independent node processes, a general-purpose
messaging CLI, multi-host deployment, or production configuration.

RAM queueing does not guarantee protection against operating-system
swapping or memory inspection.

The evaluation implementation has not received an independent
cryptographic security audit.

No original GHOST Production Core source code is included.

## Distribution

Evaluation only. No production deployment authorization.
No warranty or security certification is implied.

## Bounded hardening controls

The sender-to-relay packet uses a fixed 16-bit SHA-256 Proof-of-Work
(work factor for this limited demo, not a general DoS guarantee).
Relay ingress validates PoW, applies a bounded rate limit,
authenticates the signed inner message, and retains a bounded
replay cache.

The pending encrypted buffer is zeroized when removed.
The receiver's reconstructed plaintext buffer is zeroized
when dropped.

These controls do not guarantee protection against
every attack, memory extraction, swap, or information leak.

The implementation is not independently security certified.

## Protocol revision and remaining mandatory security work

The public wire format is now version 2: Shamir share AES wrapping keys
are derived using HKDF-SHA256 and a dedicated protocol domain. Wire
version 1 ciphertexts are intentionally rejected by the version-2 parser.
This is an evaluation-only, non-production protocol and does not claim
compatibility with GHOST Production Core.

NOT VERIFIED: independent-process or multi-host node operation; high-load
resource exhaustion; 100% prevention of crash dumps, OS swap or all
transient secret copies; formal cryptographic audit; third-party red-team.
These are release-blocking when full secure-text-mesh guarantees are claimed.


## Independent OS-process evaluation (additional)

The archive also contains `ghost_eval_isolated` (`ghost_eval_isolated.exe`
on Windows). Run this executable with no arguments to execute a bounded
three-process QUIC evaluation including a real offline receiver, receiver
restart with the same libp2p identity, encrypted DTN queueing, authenticated
recovery, signature-verified ACK, and an unauthorized fourth-node flood.

The controller passes ephemeral session configuration over child stdin pipes
and does not write private keys to a session file. This does not guarantee
zero leaked copies in RAM, OS swap, crash dumps, or other host mechanisms.

Both executables run loopback demonstrations, not arbitrary multi-host messaging.
They do not replace an independent penetration test or cryptographic audit.
