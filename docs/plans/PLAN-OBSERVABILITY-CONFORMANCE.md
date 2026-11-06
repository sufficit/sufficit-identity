# PLAN — Security observability and assurance

Status: queued; reviewed on 2026-11-06 against `a66456e`. No work item is in progress.

[Index and delivery rules](PLAN-IDENTITY.md) · [Item-by-item reconciliation](../activities/202611061100-plan-reconciliation-split.md)

## Scope and order

The profile audit API is delivered; durable security-event transport and the console timeline are separate work. Reuse existing MariaDB and replica tests rather than restating them.

## Acceptance

PII-minimized structured decisions, durable delivery/integrity/retention, alert evidence, explicit test-gap matrix and independent conformance/review outcomes.

Operational statuses describe evidence still required; historical records are not
a fresh production inventory. Source/tests present does not mean deployed.

## G1 — Security decisions must be observable

Decision logging, retention/access control and profile audit search exist. They do not implement durable outbox delivery, complete event coverage or operational alerts.

Evidence: [ManagementAuditService.cs](../../src/management/Audit/ManagementAuditService.cs), [ManagementOperationGuard.cs](../../src/management/Audit/ManagementOperationGuard.cs), [TokenIssuancePolicies.cs](../../src/sts/TokenIssuancePolicies.cs), [USAGE-AUDIT-HISTORY.md](../management/USAGE-AUDIT-HISTORY.md).

- [ ] **G1.1 · partial** — Inventory structured security-event coverage and fill gaps for issuance, actor chains, personal tokens, step-up, replay, egress, rotation and denial. Reuse current decision telemetry and management audit; maintain PII-safe event contracts.
- [ ] **G1.2 · partial** — Add durable security-audit delivery/outbox and integrity guarantees. Existing database audit retention, authorization and searchable profile snapshots are foundations, not missing features.
- [ ] **G1.3 · pending** — Alert on compatibility fallback, plaintext/TLS warnings, replay pressure, unexpected public origin and expiring keys

## G2 — Conformance and certification

OIDC/FAPI automation is documented. This does not prove SSF suite execution, formal certification or independent review; external engagements remain operational.

Evidence: [README.md](../../conformance/README.md), [conformance.yml](../../.github/workflows/conformance.yml).

- [ ] **G2.1 · pending** — Run the SSF conformance suite for the capabilities announced
- [ ] **G2.2 · operational** — Submit the applicable profiles to formal certification
- [ ] **G2.3 · operational** — Commission an external audit of DPoP, CIBA, JARM, JAR, mTLS, token exchange, SSF and the vault; fix and retest every blocking finding
- [ ] **G2.4 · operational** — Commission an independent review of the custom protocol/security code

## G3 — Distributed, browser and fault verification

Replica replay/nonce/passkey/CIBA tests, feature-off tests, MariaDB rehearsals and production revocation evidence already exist. Build a remaining browser/Redis/fault matrix instead of redoing them.

Evidence: [TwoReplicaSmokeTests.cs](../../src/tests/TwoReplicaSmokeTests.cs), [MariaDbMigrationIntegrationTests.cs](../../src/tests/MariaDbMigrationIntegrationTests.cs), [CibaTests.cs](../../src/tests/CibaTests.cs), [ManagementConsoleResponsiveTests.cs](../../src/tests/Sufficit.Identity.BrowserTests/ManagementConsoleResponsiveTests.cs), [202610281700-replica-revocation.md](../activities/202610281700-replica-revocation.md).

- [ ] **G3.1 · partial** — Complete the browser-engine matrix for passkey, 2FA, consent, CSP and step-up; existing responsive/device-flow tests and in-process protocol tests are partial evidence.
- [ ] **G3.2 · partial** — Enumerate remaining real MariaDB/Redis concurrency, feature-off, host-poisoning and fault-injection gaps. Reuse canonical/additive MariaDB, TwoReplicaSmokeTests, existing disabled-surface tests and the production replay/revocation rehearsals.
- [ ] **G3.3 · operational** — Verify the egress firewall and every approved outbound target in the production topology

## Validation required when executing

Run the tests cited in the evidence and targeted regressions for the remaining
behavior. Record exact commands, outcomes, release/commit and limitations.
For UI changes use the repository design/browser workflow; for production gates
attach dated redacted evidence and rollback. Do not close an item solely because
a related type, test name or historical deployment exists.
