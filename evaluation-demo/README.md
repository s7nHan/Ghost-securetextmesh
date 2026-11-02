# GHOST Evaluation Demo v1.0

**Real but limited technical preview.** This is an independent evaluation
implementation, not the private production application, not a general-purpose
chat client, and not a NIST/FIPS-certified product.

## Method A — clone and build from source (Rust required)

```bash
git clone https://github.com/s7nHan/Ghost-securetextmesh.git
cd Ghost-securetextmesh
cargo run --release --locked --manifest-path evaluation-demo/public-runtime/Cargo.toml --bin ghost_eval_node
```

This command runs real local QUIC, ML-KEM-768, ML-DSA-87, AES-256-GCM,
Shamir 3-of-5, disconnect/reconnect, DTN replay/ACK scenarios. The basic
executable runs three QUIC nodes within one operating-system process.

To run the separate-process Linux scenario:

```bash
ulimit -c 0
cargo run --release --locked --manifest-path evaluation-demo/public-runtime/Cargo.toml --bin ghost_eval_isolated
```

Windows PowerShell (with Rust installed):

```powershell
cargo run --release --locked --manifest-path evaluation-demo/public-runtime/Cargo.toml --bin ghost_eval_node
cargo run --release --locked --manifest-path evaluation-demo/public-runtime/Cargo.toml --bin ghost_eval_isolated
```

## Method B — prebuilt ZIP from GitHub Releases (Rust not required)

After publication, obtain the verified platform ZIP from:
https://github.com/s7nHan/Ghost-securetextmesh/releases

Linux x86_64 (inside the extracted platform folder):

```bash
chmod +x ghost_eval_node ghost_eval_isolated
./ghost_eval_node
ulimit -c 0
./ghost_eval_isolated
```

Windows x86_64 PowerShell (inside extracted folder):

```powershell
.\ghost_eval_node.exe
.\ghost_eval_isolated.exe
```

Run on a machine you control. Network / firewall restrictions may affect QUIC.
The program runs defined self-contained tests rather than interactive messaging.
A successful demo is not a production security certification.

## Developer checks

```bash
cargo test --locked --manifest-path evaluation-demo/public-crypto/Cargo.toml
cargo test --locked --manifest-path evaluation-demo/public-runtime/Cargo.toml
```

Third-party package license materials: [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## Boundaries and license

This source is only the **limited independent demo**. No Production Core, secret
keys, private validation history, production gate or deployment credentials
are included. Core-dump limits and local RAM behavior depend on the OS.
The limited evaluation permission is described in `LICENSE-EVALUATION.md`.
Publication requires explicit approval from the rights holder. Third-party crates have their own licenses.

For historical production validation evidence and the private paid technical
evaluation interest group, consult the main repository README and Discussions.

## Commercial rights and evaluation restrictions

The public demo is licensed for technical evaluation only. Downloading, testing, cloning or running it grants no ownership, commercial use, redistribution, integration, resale or Production Core rights in GHOST-owned materials. See `LICENSE-EVALUATION.md`. Third-party components retain their own license terms.
