# Security policy

This is a reference framework, not a claim of production security certification or unbreakable DRM. Only the latest `main` and latest `0.1.x` release are maintained initially.

Report vulnerabilities through the repository's private vulnerability reporting feature, when enabled. Do not include live credentials or customer records. If private reporting is unavailable, open a minimal issue requesting a private reporting channel without exploit details. Do not use public Issues for active secrets.

## Trust boundaries

- Clients, hardware fingerprints, submitted user IDs, payment screenshots and distribution markers are untrusted input.
- External identity proof is verified by a provider adapter. Invitations and user sessions are high-entropy, hashed at rest, expiring credentials. Provider tokens are not persisted.
- Administrator API authentication is a separate deployment secret. The reference server has no human operator MFA or individual admin accounts. A production control plane must add those controls and authorization scopes.
- Devices prove possession of an Ed25519 private key. This is not TPM attestation; a copied software private key can impersonate a device. Hardware collection and platform key storage are integration responsibilities.
- License refresh checks current entitlement and binding. Previously issued offline licenses remain usable until expiry, and a modified client can bypass local policy.
- Artifact attribution supports investigation. A marker can be copied, removed or planted; do not automatically ban an account based on a marker alone.

## Deployment requirements

Keep signing keys, admin tokens, Bot tokens, payment credentials, databases and generated user files outside Git. Use TLS, authenticated administration, protected storage, encrypted backups and tested restoration. Redact proxy and application logs; never put access tokens in URLs. Restrict administrative and build-worker access independently from public user endpoints.

Pin trusted server public keys in clients through an authenticated release process. Do not trust a public key merely because it arrived with a license. Review key rotation and outage recovery before taking payment for a permanent license.

The included source checker catches selected credential formats and runtime files; it is not a complete secret scanner. Dependency audit covers known advisories at the time of the check, not all vulnerabilities. Tests use synthetic users, payments and mocked KOOK responses.
