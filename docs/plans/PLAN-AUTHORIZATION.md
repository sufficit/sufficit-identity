# PLAN — Authorization and security policy

Status: queued; A4.1 assurance derivation/session ownership completed on 2026-11-06; issuance and existing-token audit remains.

[Index and delivery rules](PLAN-IDENTITY.md) · [Item-by-item reconciliation](../activities/202611061100-plan-reconciliation-split.md)

## Scope and order

Start with the A2 telemetry review; credential-reference parity precedes console adoption. MFA consolidation must preserve remembered-device and credential-minting distinctions.

## Acceptance

Scope grants cannot exceed operator authority; all secret-entry paths enforce provenance; MFA and CSP exceptions have tested, bounded behavior.

Operational statuses describe evidence still required; historical records are not
a fresh production inventory. Source/tests present does not mean deployed.

## A2 — Operator-aware client scope and secret authorization

Create/update support secretReference; rotate/additional-credential commands still accept plaintext. The October deployment record does not prove that the November enforcement gate ran.

Evidence: [ClientManagementContracts.cs](../../src/application/Sufficit.Identity.Application.Abstractions/Management/Clients/ClientManagementContracts.cs), [ClientSecretReferenceTests.cs](../../src/tests/ClientSecretReferenceTests.cs), [202610281800-operator-scope-grant.md](../activities/202610281800-operator-scope-grant.md).

- [ ] **A2.1 · operational** — Reconcile the observed denials (audit `reasonCode like 'scope_grant_%'`, `operationOutcome = 'observed'`), then set `ClientScopeGrants:Mode=Enforce` on the three nodes
- [ ] **A2.2 · operational** — Migrate plaintext-secret callers (`client_secret_plaintext_deprecated`) to `secretReference` and remove the adapter after `ClientSecrets:PlaintextExpiresAtUtc`
- [ ] **A2.3 · operational** — Inventory the real production manifests and adopt existing managed clients explicitly before enabling client-definition enforcement
- [ ] **A2.4 · pending** — Bring `/secret/rotate` and `/credentials` onto `secretReference`; they still accept an operator-supplied secret

## A4 — Step-up enforcement and one MFA evidence policy

STS and SCIM now delegate evidence reading to MfaEvidencePolicy; see the [SCIM consolidation activity](../activities/202611061120-scim-shared-mfa-evidence.md). Stale-credential tests exist, but the requested browser-to-Management/SCIM end-to-end chain is not established.

Evidence: [ScimServiceCollectionExtensions.cs](../../src/scim/ScimServiceCollectionExtensions.cs), [MfaEvidence.cs](../../src/sts/Security/MfaEvidence.cs), [CredentialMutationSecurityTests.cs](../../src/tests/CredentialMutationSecurityTests.cs).

- [ ] **A4.1 · partial** — Reader consolidation, single-factor refusal and conservative assurance/session ownership are complete ([activity](../activities/202611061129-session-assurance-evidence-ownership.md)). Finish the writer audit: passkeys still emit hwk without hardware/software distinction; verify when passkey authentication evidence is set relative to cookie issuance. Review existing cookies/refresh tokens and direct AAL/ACR consumers (including AuthorizationReauthenticationPolicy.CurrentAssuranceLevel) rather than assuming the corrected factory retroactively repairs issued evidence. Preserve remembered-MFA versus fresh credential-minting requirements.
- [ ] **A4.2 · partial** — Complete a browser-to-Management/SCIM MFA authorization test chain. Reuse CredentialMutationSecurityTests for stale credential mutations rather than recreating its covered cases.

## D1 — CSP from telemetry to enforcement

AcknowledgeReportOnly remains a boolean without an expiry. Existing CSP tests do not bound that exception lifetime.

Evidence: [HttpSurfaceOptions.cs](../../src/sts/Options/HttpSurfaceOptions.cs), [CspHeaderTests.cs](../../src/tests/CspHeaderTests.cs).

- [ ] **D1.1 · pending** — Make the report-only rollback switch bounded: `AcknowledgeReportOnly` has no expiry (reports already strip query and userinfo)

## Validation required when executing

Run the tests cited in the evidence and targeted regressions for the remaining
behavior. Record exact commands, outcomes, release/commit and limitations.
For UI changes use the repository design/browser workflow; for production gates
attach dated redacted evidence and rollback. Do not close an item solely because
a related type, test name or historical deployment exists.
