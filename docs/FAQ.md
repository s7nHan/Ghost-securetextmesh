# FAQ

## Is GHOST open source?

No. This repository is a public technical showcase. The production implementation remains private. The small Rust example in `examples/rust-showcase/` is a non-production lifecycle model, not the GHOST production source.

## What language is GHOST written in?

The production implementation is Rust-based and uses Tokio for asynchronous orchestration. The public repository includes a safe Rust lifecycle example so the showcase reflects the implementation language without exposing the private production code.

## Why is the Python helper excluded from GitHub's language bar?

`scripts/preflight_public.py` is repository publishing/preflight tooling, not GHOST product implementation. `.gitattributes` marks that helper as non-detectable for GitHub Linguist so the language bar is not dominated by publishing tooling.

## Which cryptographic components are publicly described?

The public system description includes ML-DSA, ML-KEM, AES-256-GCM, Shamir Secret Sharing, signature/message verification, nonce/replay protection, Proof-of-Work controls, and key lifecycle handling. Sensitive implementation details remain private.

## Is GHOST only a concept?

No. The repository includes sanitized output from internal engineering validation, including a real 3-node end-to-end PASS result and the recorded validation snapshot.

## Is the validation an independent certification?

No. The published results are self-run engineering validation and are explicitly not presented as independent certification, formal verification, third-party penetration testing or government/security accreditation.

## When will the first demo / Technical Evaluation open?

The public showcase starts with an initial **1–2 week demand-validation window**. Stars, technical Issues/Discussions and especially qualified Evaluation Interest are reviewed. If sufficient genuine interest is confirmed and the release gate remains ready, the first controlled demo / Technical Evaluation access window will be announced. The opening date is intentionally interest-dependent rather than committed to a fixed day in advance.

## Is a technical evaluation available now?

A controlled, time-bound technical evaluation is planned around a **USD 2,000 reference price**. Joining the public interest group does not require payment and does not guarantee access.

## How do I express interest?

For the planned USD 2,000 evaluation, join **Discussions → Evaluation Interest** using the structured group form. For other technical, integration, licensing or collaboration questions, use **Issues → New issue → Evaluation / Collaboration Interest**. Both paths remain inside the repository.

## Should I post confidential information in an Issue?

No. Public Issues must not contain credentials, private keys, classified information, exploitable security details or sensitive infrastructure data.

## Where is the production source code?

It is intentionally not included in this public showcase repository.
