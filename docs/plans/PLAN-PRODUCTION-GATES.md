# PLAN — Production rollout and legacy retirement

Status: queued; reviewed on 2026-11-06 against `a66456e`. No work item is in progress.

[Index and delivery rules](PLAN-IDENTITY.md) · [Item-by-item reconciliation](../activities/202611061100-plan-reconciliation-split.md)

## Scope and order

Collect current redacted evidence before changing deployment policy or retiring compatibility. Calendar dates are eligibility gates, never proof an action ran.

## Acceptance

Every operation has target/release, before-after evidence and rollback under the production evidence runbook; external decisions and disclosures have a named owner.

Operational statuses describe evidence still required; historical records are not
a fresh production inventory. Source/tests present does not mean deployed.

## C4 — Verified transport everywhere

Transport policy and its tests exist; the last recorded deployment choice must be checked at execution. No live connection strings were read for this review.

Evidence: [DatabaseTransportPolicyTests.cs](../../src/tests/DatabaseTransportPolicyTests.cs), [202610231500-plan-reassessment.md](../activities/202610231500-plan-reassessment.md).

- [ ] **C4.1 · operational** — Select `RequireVerifiedTls` — or the audited `PrivateSocket` exception — in each production deployment, after the CA or socket is provisioned. The last recorded deployment used `db-proxy-local` without an explicit `SslMode`; confirm current transport before selecting the policy.

## C5 — Legacy credential inventory and rotation **(operational)**

An inventory/rotation completion artifact is still required; absence of one is not proof credentials are compromised or still unchanged.

Evidence: [RUNBOOK-PRODUCTION-EVIDENCE.md](../runbooks/RUNBOOK-PRODUCTION-EVIDENCE.md).

- [ ] **C5.1 · operational** — Inventory and rotate the legacy database and provider credentials and certificates, migrate `deploy/local/` to the approved secret store, and attach a redacted manifest with owner, version, state and retirement date

## F11 — Breached-password availability policy

Failure modes are implemented; changing the deployed mode requires current availability/latency evidence. The old LocalFallback record is historical.

Evidence: [BreachedPasswordValidator.cs](../../src/sts/BreachedPasswordValidator.cs), [202609201700-breached-password-fallback.md](../activities/202609201700-breached-password-fallback.md).

- [ ] **F11.1 · operational** — Move to `FailClosed` once the `breached_password_check` telemetry characterises latency and availability (last recorded mode: `LocalFallback`; recheck deployment and telemetry before changing it: [`202609201200`](../activities/202609201200-breach-check-in-production.md), [`202609201700`](../activities/202609201700-breached-password-fallback.md))

## G4 — Legacy cutover operational gates **(operational)**

Forwarded-origin/proxy verification has dated end-to-end evidence. Encryption overlap and token revocation are not equivalent to signing JWKS rotation or a complete client inventory.

Evidence: [202610222030-credential-abuse-protection.md](../activities/202610222030-credential-abuse-protection.md), [202610231600-encryption-certificate-separation.md](../activities/202610231600-encryption-certificate-separation.md), [202610281700-replica-revocation.md](../activities/202610281700-replica-revocation.md).

- [ ] **G4.1 · operational** — Every active client has an assigned owner and a documented final state
- [ ] **G4.2 · operational** — Confidential clients have newly issued, post-migration credentials
- [ ] **G4.3 · operational** — Redirect, logout and CORS allow-lists verified per client
- [ ] **G4.4 · operational** — Token format validated by every resource server (reference vs JWT)
- [ ] **G4.5 · partial** — Prove signing JWKS active/retiring overlap and rotation at consumers. Do not count the existing encryption-certificate overlap or token-revocation rehearsal as signing-key evidence.

## G7 — Coordinated disclosure **(operational)**

Disclosure is an external owner decision. Keep confidential identifiers and reproduction details out of the public review record.

Evidence: [RUNBOOK-PRODUCTION-EVIDENCE.md](../runbooks/RUNBOOK-PRODUCTION-EVIDENCE.md).

- [ ] **G7.1 · operational** — Decide on coordinated disclosure before adding the confidential review identifier or any reproduction detail to this public repository

## Calendar carried forward

All dates below are original eligibility dates, not verified execution dates.
The seven original rows are preserved; A2/C2 remain their single task owners.

| When | Action | Owner |
|---|---|---|
| ~2026-11-03 | Delete the 10 disabled underscore client ids if they issued no token since 2026-10-27 | [`202610271500`](../activities/202610271500-hyphenated-client-ids.md) |
| ~2026-11-04 | Read the observed scope-grant rows; set `ClientScopeGrants:Mode=Enforce` | A2 |
| after the client-id cleanup | Remove the legacy client/scope acceptance in endpoints (`LegacyClientId`) and background (`Legacy*`) | [`202610271500`](../activities/202610271500-hyphenated-client-ids.md) |
| from 2026-11-20 | Drop `certificate.pfx` and `certificate-old.pfx` from `EncryptionPaths` | C2 |
| when the August agent authorizations stop refreshing | Remove the `sufficit_ai_openai_bridge` scope and permission | [`202610271500`](../activities/202610271500-hyphenated-client-ids.md) |
| before 2027-04-30 | Migrate every `client_secret_plaintext_deprecated` caller to `secretReference`; the adapter refuses after that date | A2 |
| open | Inventory the production provisioning manifests and adopt existing clients explicitly | A2 |


Before action, refresh last-use/expiry evidence and follow [production evidence](../runbooks/RUNBOOK-PRODUCTION-EVIDENCE.md). The November 3/4 rows are overdue for verification, not automatically authorized deletion/enforcement.

## Validation required when executing

Run the tests cited in the evidence and targeted regressions for the remaining
behavior. Record exact commands, outcomes, release/commit and limitations.
For UI changes use the repository design/browser workflow; for production gates
attach dated redacted evidence and rollback. Do not close an item solely because
a related type, test name or historical deployment exists.

## Authorized publication — 2026-11-06

1. **completed** — Verify deployment inventory, active revisions, CSP startup
   compatibility and local SUI source; identify schema changes before activation.
2. **in progress** — Build the release with local SUI and prepare the same verified
   archive on all three nodes using the cluster wrappers.
3. **pending** — Activate sequentially with rollback, verify revision/readiness/
   certificate/JWKS uniformity, record activity and push delivery documentation.

Publication authorized by the user. Preserve per-node configuration and secrets;
do not enable unrelated enforcement gates or change user/client records.

Preflight evidence: all three apps nodes are active, CSP is enforced and the
legacy acknowledgement bridge is disabled. All three active paths are ordinary
directories outside the versioned releases root, with no REVISION. The current
cluster prepare/activate wrappers reject this layout. Activation is blocked
until the legacy layout is migrated with a verified rollback baseline; no
service has been changed. Local SUI revision: `91f76e061b5561cf8adeafdf311815407061856a`.
