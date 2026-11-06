# PLAN — Keys, vault rotation and encryption budget

Status: queued; reviewed on 2026-11-06 against `a66456e`. No work item is in progress.

[Index and delivery rules](PLAN-IDENTITY.md) · [Item-by-item reconciliation](../activities/202611061100-plan-reconciliation-split.md)

## Scope and order

Do the re-wrap/data-key race test before new key providers. The old token-decryption certificates must stay until their recorded expiry gate is rechecked.

## Acceptance

Cross-replica rotation, decrypt/restore and rollback evidence, audited authority separation, and an aggregate durable encryption budget before automatic rotation.

Operational statuses describe evidence still required; historical records are not
a fresh production inventory. Source/tests present does not mean deployed.

## C1 — Vault production enablement and rotation

Re-wrap, loss and key leases are covered separately. They do not prove the mixed re-wrap/data-key rotation race or production authority separation.

Evidence: [VaultTests.KekRewrap.cs](../../src/tests/VaultTests.KekRewrap.cs), [VaultSymmetricKeyLeaseTests.cs](../../src/tests/VaultSymmetricKeyLeaseTests.cs), [202610231900-vault-kek-escrow.md](../activities/202610231900-vault-kek-escrow.md).

- [ ] **C1.1 · operational** — Separate database-reader authority from KEK authority in production
- [ ] **C1.2 · pending** — Test a re-wrap racing a data-key rotation on another replica (loss, old-version decrypt and restore are covered: [`202610232000`](../activities/202610232000-vault-kek-rotation.md))

## C2 — Signing and encryption key separation

Purpose-separated token certificates and overlap were delivered. Retain provider lifecycle, cross-purpose rehearsal and dated retirement gates, rather than recreating separation.

Evidence: [IdentityCertificateMaterial.cs](../../src/sts/IdentityCertificateMaterial.cs), [CertificatesOptions.cs](../../src/sts/Options/CertificatesOptions.cs), [202610231600-encryption-certificate-separation.md](../activities/202610231600-encryption-certificate-separation.md).

- [ ] **C2.1 · operational** — Drop `certificate.pfx` and `certificate-old.pfx` from `EncryptionPaths`: the 2026-10-23 record places the last valid token expiry at 2026-11-19 17:39 UTC. Recheck issuance/expiry before removal; the recorded earliest date is 2026-11-20
- [ ] **C2.2 · partial** — Extend the already purpose-separated token certificates into an explicitly managed active/retiring lifecycle with stable kid/JWKS behavior and a KMS/HSM-backed production provider. Preserve existing overlap support.
- [ ] **C2.3 · partial** — Verify the token, Data Protection and TLS material inventory and test cross-purpose compromise/rollback. Token signing/encryption separation is delivered; identify residual gaps before changing key architecture.
- [ ] **C2.4 · operational** — Audit and rotate any production signing material that may have been created through the legacy helper path, recording only thumbprints and versions — never keys or passwords
- [ ] **C2.5 · operational** — Inventory certificates, prove the signing/KEK separation and execute a restore/disaster-recovery rehearsal

## F12 — GCM budget

Local ConcurrentDictionary counts and metrics export exist; a restart-safe, replica-aggregate budget authority and automated rotation are still absent.

Evidence: [VaultCryptographyTelemetry.cs](../../src/vault/VaultCryptographyTelemetry.cs), [VaultCryptographyTelemetryTests.cs](../../src/tests/VaultCryptographyTelemetryTests.cs).

- [ ] **F12.1 · pending** — Auto-rotate the DEK at its budget, or drive rotation from a durable counter. `VaultCryptographyTelemetry` warns at 80% and logs critical at 100%, but it counts **per process** in a `ConcurrentDictionary`, so three replicas reach the real budget while each reports a third of it. Automatic rotation is disabled on purpose until the aggregated metric exists

## Validation required when executing

Run the tests cited in the evidence and targeted regressions for the remaining
behavior. Record exact commands, outcomes, release/commit and limitations.
For UI changes use the repository design/browser workflow; for production gates
attach dated redacted evidence and rollback. Do not close an item solely because
a related type, test name or historical deployment exists.
