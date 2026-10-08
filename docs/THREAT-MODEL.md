# Threat Model

This is a public, high-level threat model for the GHOST pre-launch showcase.

## Threats considered at system level

- Message tampering
- Replay attempts
- Invalid / malformed messages
- Intermittent connectivity
- Node / path disruption
- Resource abuse
- Unauthorized message modification
- Fragment integrity problems
- Message verification failure

## Security assumptions

A secure deployment still depends on factors outside the application itself, including:

- Host operating-system security
- Secure key provisioning
- Endpoint access control
- Correct deployment configuration
- Network and firewall policy
- Secure build / release handling
- Administrator operational security

## Out of scope for public claims

The pre-launch repository does not claim immunity from all endpoint compromise, nation-state attack, side-channel attack, implementation flaw, supply-chain compromise, or unknown cryptographic vulnerability.

Security-sensitive threat analysis may be shared under controlled evaluation terms.
