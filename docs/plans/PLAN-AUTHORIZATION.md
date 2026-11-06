# PLAN — Authorization and security policy

Status: operational gates pending; A2.4, A4.1, A4.2 and D1.1 completed on 2026-11-06.

[Index and delivery rules](PLAN-IDENTITY.md) · [Item-by-item reconciliation](../activities/202611061100-plan-reconciliation-split.md)

## Scope and order

Start with the A2 telemetry review; credential-reference parity precedes console adoption. MFA consolidation must preserve remembered-device and credential-minting distinctions.

## Acceptance

Scope grants cannot exceed operator authority; all secret-entry paths enforce provenance; MFA and CSP exceptions have tested, bounded behavior.

Operational statuses describe evidence still required; historical records are not
a fresh production inventory. Source/tests present does not mean deployed.

## A2 — Operator-aware client scope and secret authorization

Create/update, rotation and additional credentials support secretReference. Plaintext HTTP compatibility is audited and expires. The October deployment record does not prove that the November enforcement gate ran.

Evidence: [ClientManagementContracts.cs](../../src/application/Sufficit.Identity.Application.Abstractions/Management/Clients/ClientManagementContracts.cs), [ClientSecretReferenceTests.cs](../../src/tests/ClientSecretReferenceTests.cs), [202610281800-operator-scope-grant.md](../activities/202610281800-operator-scope-grant.md).

- [ ] **A2.1 · operational** — Reconcile the observed denials (audit `reasonCode like 'scope_grant_%'`, `operationOutcome = 'observed'`), then set `ClientScopeGrants:Mode=Enforce` on the three nodes
- [ ] **A2.2 · operational** — Migrate plaintext-secret callers (`client_secret_plaintext_deprecated`) to `secretReference` and remove the adapter after `ClientSecrets:PlaintextExpiresAtUtc`
- [ ] **A2.3 · operational** — Inventory the real production manifests and adopt existing managed clients explicitly before enabling client-definition enforcement
A2.4 is closed in the [client lifecycle reference activity](../activities/202611061213-client-lifecycle-secret-references.md).

## A4 — Step-up enforcement and one MFA evidence policy

A4.1 and A4.2 are closed in the [MFA evidence and browser-chain activity](../activities/202611061148-mfa-evidence-browser-chain.md). The shared reader, factor policy, session ownership, verified passkey issuance, conservative AAL/ACR consumers and Chromium-to-Management/SCIM chain are validated. Deployment and historical-token revocation are separate operational actions.

Earlier delivery records: [reader consolidation](../activities/202611061120-scim-shared-mfa-evidence.md), [single-factor refusal](../activities/202611061124-single-factor-mfa-refusal.md), [session ownership](../activities/202611061129-session-assurance-evidence-ownership.md).

## D1 — CSP from telemetry to enforcement

D1.1 is closed in the [bounded CSP calibration activity](../activities/202611061207-bounded-csp-calibration.md).
Report-only startup exceptions require owner, reason and expiry through the
existing posture mechanism; the legacy boolean cannot bypass expiry. Production
calibration and configuration migration remain operational rollout actions.

## Validation required when executing

Run the tests cited in the evidence and targeted regressions for the remaining
behavior. Record exact commands, outcomes, release/commit and limitations.
For UI changes use the repository design/browser workflow; for production gates
attach dated redacted evidence and rollback. Do not close an item solely because
a related type, test name or historical deployment exists.
