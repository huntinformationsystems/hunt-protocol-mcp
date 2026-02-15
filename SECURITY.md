# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the Provara MCP server or the underlying protocol, please report it responsibly. **Do not open a public GitHub issue for security vulnerabilities.**

Send an email to **hello@provara.dev** with "SECURITY" in the subject line. Include:

- A description of the vulnerability
- Steps to reproduce (or a proof-of-concept)
- The version(s) affected
- Any potential impact assessment you can provide

We will acknowledge receipt within 48 hours and provide an initial assessment within 7 business days.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

Older versions, pre-release builds, and forks are not covered by this policy.

## Responsible Disclosure Timeline

We follow a 90-day responsible disclosure policy:

1. **Day 0:** Vulnerability reported to hello@provara.dev.
2. **Day 0-7:** The Provara team acknowledges receipt and begins triage.
3. **Day 7-30:** We develop and internally test a fix.
4. **Day 30-90:** We release the fix, coordinate disclosure with the reporter, and publish an advisory.
5. **Day 90:** If no fix has been released, the reporter may disclose publicly.

We will credit reporters in the advisory unless they request anonymity.

## Cryptographic Primitives

Provara relies on the following cryptographic standards:

| Primitive | Standard | Usage |
|-----------|----------|-------|
| Ed25519 digital signatures | RFC 8032 | Event signing, manifest signing, key rotation |
| SHA-256 hashing | FIPS 180-4 | Content addressing, Merkle tree construction, file integrity |
| Canonical JSON serialization | RFC 8785 | Deterministic pre-image for hashing and signing |

All cryptographic operations are performed by the `cryptography` library (PyCA), which wraps OpenSSL. We do not implement any cryptographic primitives ourselves.

## Threat Model

### What Provara protects against

- **Event tampering:** Every event is content-addressed (SHA-256) and signed (Ed25519). Modifying an event invalidates its hash and signature.
- **Signature forgery:** Ed25519 signatures bind events to a specific key. Without the private key, valid signatures cannot be produced.
- **Chain manipulation:** Events form a causal chain via `prev_event_id` references. Inserting, reordering, or removing events breaks the chain and is detected by the integrity verifier.
- **Manifest tampering:** The manifest contains SHA-256 hashes for all vault files. The manifest itself is signed. Any modification to vault files is detectable.
- **Unauthorized key usage:** Key rotation events create a cryptographic audit trail. Revoked keys cannot produce events that pass verification.

### What Provara does NOT protect against

- **Denial of service (DoS/DDoS):** The MCP server is a local stdio process, not a network service. Resource exhaustion attacks on the host system are outside our scope.
- **Side-channel timing attacks on signing:** We rely on the `cryptography` library's Ed25519 implementation. While it uses constant-time operations where possible, we do not make formal guarantees against timing side-channels.
- **Physical access to vault files:** If an attacker has filesystem access, they can read vault contents (events are not encrypted at rest), delete files, or replace the entire vault. Provara detects tampering but does not prevent it. Encryption at rest is a planned future feature.
- **Key compromise:** If an attacker obtains the Ed25519 private key, they can produce valid signatures. Protect your signing key. Key rotation (rekey) can revoke a compromised key, but events signed before revocation remain valid.
- **Supply-chain attacks on dependencies:** We minimize dependencies (only `fastmcp` and `cryptography`), but we do not formally verify the dependency tree.

## Bug Bounty

We do not currently operate a bug bounty program. We plan to introduce one as the project matures. In the meantime, we are grateful for responsible reports and will publicly credit researchers who help us improve Provara's security.

## Contact

For all security matters: **hello@provara.dev** (subject: SECURITY)
