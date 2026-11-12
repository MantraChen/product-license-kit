# Changelog

## 0.7.0 — source version, 2026-11-12

No release tag or npm publication is implied.

- Integrate the product-tested Beta channel offers into the framework repository: same-edition top-ups, Beta direct purchases, source-channel prerequisites and channel-aware cheapest upgrades.
- Recheck eligibility at order creation and fulfillment; preserve the original Stable purchase provenance when granting Beta.
- Document the previously merged TPM-compatible RSA-PSS device proofs and scoped operation/cancellation envelopes; server envelope trust remains Ed25519.
- Refresh architecture, integration, protocol, roadmap and system guides against the source. No database migration is introduced by this release.

## 0.6.0 — historical source baseline

- Explicit audited `setEntitlementAccess` changes, including restoration, with idempotency and paid provenance preservation.

## 0.5.0 — historical source baseline

- Channel- and fingerprint-scoped device licenses, security recovery revocation, exceptional payment reconciliation and migration 6.

## 0.4.0 — historical source baseline

- Order expiry and reviewed late payments, migration 5 and 256 MiB backup capacity.

## 0.3.0 — historical source baseline

- Confirmed device resets and prepaid re-enrollment with migration 4.


## 0.2.0 — source version, 2026-10-31

This records the package/source version; no release tag or registry publication is implied.

- Import externally verified permanent ownership with stable evidence attribution, without fabricating payments or replacing paid provenance. Revoked rights are not restored by recognition.
- Track Beta access per edition; Beta includes stable access only for that edition and is not inherited by upgrades.
- Select the cheapest eligible fixed-price upgrade, with deterministic ties and a mixed-currency guard.
- Apply migration 3: nullable entitlement order IDs, import evidence and channel tables while preserving paid records.
- Add synchronized Markdown and Word system guides and correct current integration, API and operations documentation.


## 0.1.1 — 2026-10-30

- Enforce persistent account suspension and an optional fail-closed product account policy inside authorization, activation and distribution operations, including idempotent replays.
- Add additive migration records, nested transactions for atomic product integration, and revocation of sessions, challenges and device bindings on suspension.
- Provide a router-metadata-based browser CSRF guard and bounded scrypt hashing for web integrations.
- Protect service data with Windows DACLs / Unix private modes before initialization; support atomic private file replacement and single-process service locks.
- Add consistent SQLite snapshots, authenticated encrypted recovery bundles, restore-to-new-directory and signing-key rotation tools.
- Configure explicit trusted proxy CIDRs while rejecting implicit or global trust.
- Add security regression, migration and backup/recovery tests. This does not implement hardware attestation or eliminate the documented offline lease window.

## 0.1.0 — 2026-10-30

- Initial source-available framework under PolyForm Noncommercial 1.0.0 with explicit PR contribution terms.
- Configurable products, editions, fixed-price upgrades and shared/independent device groups.
- Verified invitation registration, separate user/admin authentication and identity recovery audit.
- Transactional manual payment fulfillment, reference deduplication and idempotent commands.
- Device proof of possession, calendar-month cooldown and purchased/admin rebind credits.
- Signed device leases, client verification, immutable distribution manifests and attribution snapshots.
- Optional KOOK identity and notification adapters; synthetic local HTTP demonstration.
- Windows/Linux CI, dependency checks, public-file guard and deployment/integration documentation.
