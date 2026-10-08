# Public Claims & Evidence Gate

Use this document as the final gate before making any claim public.

## Rule

A public statement belongs in the repository only if it is:

1. implemented in the current system;
2. demonstrated or internally validated where claimed;
3. described without overstating what the evidence proves; and
4. safe to disclose publicly.

## Approved claim classes

### Implemented capability

Example:

> `GHOST includes ML-DSA digital signatures and ML-KEM key-establishment workflows.`

Use when the capability exists in the current implementation.

### Internally validated behavior

Example:

> `Multi-node message transfer has been internally validated.`

Use only when a repeatable internal test supports the statement.

### Public evidence available

Example:

> `A sanitized 3-node E2E output showing disconnect / reconnect recovery is available here.`

Use only while the corresponding public text evidence is present in this repository.

## Claims that require independent evidence before publication

Do not state these unless independent evidence exists and is linked with scope and date:

- independently certified
- penetration-tested by a third party
- formally verified
- government accredited
- military certified
- impossible to intercept
- impossible to break
- zero persistence under every host configuration
- immune to nation-state attack
- production-approved for a named external organization

## Claim review table

| Claim | Implementation present? | Internal validation? | Public evidence? | Public wording approved? |
|---|---:|---:|---:|---:|
| Rust / Tokio implementation foundation | [ ] | [ ] | [ ] | [ ] |
| Multi-node transfer | [ ] | [ ] | [ ] | [ ] |
| Disruption / recovery | [ ] | [ ] | [ ] | [ ] |
| ML-DSA signing / verification | [ ] | [ ] | [ ] | [ ] |
| ML-KEM key-establishment behavior | [ ] | [ ] | [ ] | [ ] |
| AES-256-GCM behavior | [ ] | [ ] | [ ] | [ ] |
| Shamir threshold secret sharing | [ ] | [ ] | [ ] | [ ] |
| Fragmentation / reassembly | [ ] | [ ] | [ ] | [ ] |
| Replay protection | [ ] | [ ] | [ ] | [ ] |
| Invalid / tampered rejection | [ ] | [ ] | [ ] | [ ] |
| RAM-first message lifecycle | [ ] | [ ] | [ ] | [ ] |
| Key lifecycle behavior | [ ] | [ ] | [ ] | [ ] |

Complete this table using the final private test evidence before publication.
