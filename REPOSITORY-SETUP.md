# GitHub Repository Setup

## Suggested repository name

`ghost-secure-text-mesh-showcase`

## Suggested description

> Resilient secure text communication for disrupted multi-node environments. Private implementation, public technical evidence.

## Suggested topics

`rust` `tokio` `cybersecurity` `cryptography` `post-quantum-cryptography` `ml-dsa` `ml-kem` `aes-256-gcm` `shamir-secret-sharing` `secure-communications` `secure-messaging` `mesh-networking` `peer-to-peer` `p2p` `dtn` `delay-tolerant-networking` `distributed-systems` `resilient-systems` `network-security` `mission-critical`

## GitHub language bar

The production implementation is Rust-based. This public showcase includes a safe, non-production Rust lifecycle example under `examples/rust-showcase/`.

The Python file in `scripts/` is publishing/preflight tooling rather than product implementation, so `.gitattributes` marks it `linguist-detectable=false`. This prevents repository tooling from incorrectly dominating the GitHub language summary.

Do not add fake Rust files or copy private production source merely to influence GitHub Linguist.

## Required GitHub features

- **Issues: ON**
- **Discussions: ON**
- Wiki: OFF unless needed later
- Projects: OFF unless needed later
- Private Vulnerability Reporting: ON if available and desired

## Required Discussions category

Create a Discussions category named exactly:

**Evaluation Interest**

Its category slug should be:

`evaluation-interest`

The repository already contains:

`.github/DISCUSSION_TEMPLATE/evaluation-interest.yml`

GitHub uses that file as the structured category form for new interest entries.

## Repository-native interest flow

```text
README
  ↓
Validation / architecture / evidence
  ↓
Evaluation Interest Group
  ↓
Discussions → Evaluation Interest
  ↓
One public interest entry per participant
  ↓
Initial 1–2 week demand-validation window
  ↓
First controlled demo / Technical Evaluation access if qualified interest is sufficient
```

The category page itself functions as the public group/list. No external form, email list, landing page, or checkout is required.

## Issues remain separate

Keep **Issues** enabled. The existing `Evaluation / Collaboration Interest` issue form remains available for questions and conversations that are not simply a group-membership / evaluation-interest entry.
