# Public Evidence Manifest

This manifest maps public claims to sanitized evidence included in the showcase repository.

| ID | Evidence | What it supports | Status |
|---|---|---|---|
| VAL-001 | `test-results/public-validation-summary.txt` | Internal validation snapshot: 35/35 tests, 2,360 accelerated executions, 5/5 real 3-node chaos/recovery cycles, 0 source-integrity drift, release gate PASS | READY |
| E2E-001 | `test-results/three-node-e2e-pass.txt` | Real 3-node end-to-end PASS with disconnect/reconnect, multi-fragment delivery and authenticated IPC/admin | READY |

## Evidence policy

- Evidence is text-first and sanitized.
- Production source code, credentials, secrets and deployment-sensitive details are excluded.
- Internal validation is never described as independent certification.
