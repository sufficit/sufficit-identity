# Plan reconciliation and focused workstreams

Reviewed 2026-11-06 at `a66456e`; documentation-only change. All 105 original
work checkboxes, seven closure criteria and seven calendar entries were retained
in this disposition record. Source, tests and existing dated delivery records
were reviewed across all 37 sections. No production settings/accounts were read
or changed, no operational gate was inferred complete from elapsed dates.

## Findings

- Closed E3.1/E3.3: filtered client metrics and context-linked session/authorization
  revocation exist in the console and backend.
- Closed F5.1: production HTTP startup rejects AutoMigrate; preserve the dedicated
  migration process and Development behavior. F5.2 still owns missing failure tests.
- Closed G4.6 against the dated 2026-10-22 production proxy verification; this is
  historical proof, not an assertion that today's configuration was inspected.
- Merged E2.7 into E4.2, eliminating duplicate typed application-claim work.
- E4.5 became an acceptance rule: profiles must have validation/explanation/tests.
- Narrowed sessions, audit, credential UI, key separation, vulnerability scanning,
  MFA and distributed verification to their actual remaining gaps.
- Kept B9 and G6 explicitly deferred; new features are not retroactively made
  production requirements. Operational evidence and owner decisions remain explicit.

Disposition counts: closed=4, decision=2, deferred=5, dependency=2, guardrail=1, merged=1, operational=22, partial=26, pending=42.
There are 99 remaining work checkboxes, plus seven shared closure criteria.
The seven calendar rows remain schedules/conditions, not additional duplicate tasks.

## Evidence by section

### A2

Create/update support secretReference; rotate/additional-credential commands still accept plaintext. The October deployment record does not prove that the November enforcement gate ran.

[ClientManagementContracts.cs](../../src/application/Sufficit.Identity.Application.Abstractions/Management/Clients/ClientManagementContracts.cs), [ClientSecretReferenceTests.cs](../../src/tests/ClientSecretReferenceTests.cs), [202610281800-operator-scope-grant.md](../activities/202610281800-operator-scope-grant.md).

### A3

Per-operation enforcement is implemented. What remains is deployment/consumer inventory, not another authorization implementation.

[ScimOperationAuthorization.cs](../../src/scim/ScimOperationAuthorization.cs), [ScimOperationAuthorizationTests.cs](../../src/tests/ScimOperationAuthorizationTests.cs), [202609201900-scim-per-operation.md](../activities/202609201900-scim-per-operation.md).

### A4

STS delegates evidence reading to MfaEvidencePolicy; SCIM still has its own method set. Stale-credential tests exist, but the requested browser-to-Management/SCIM end-to-end chain is not established.

[ScimServiceCollectionExtensions.cs](../../src/scim/ScimServiceCollectionExtensions.cs), [MfaEvidence.cs](../../src/sts/Security/MfaEvidence.cs), [CredentialMutationSecurityTests.cs](../../src/tests/CredentialMutationSecurityTests.cs).

### B3

The holder-bound subject-token test remains explicitly skipped with the resolved-payload ath failure documented in its reason.

[TokenExchangeSubjectTokenTests.cs](../../src/tests/TokenExchangeSubjectTokenTests.cs).

### B5

Initiator authentication, foreign clients, polling and one-winner consumption have tests; those do not establish external interoperability or approval-fatigue protection.

[CibaTests.cs](../../src/tests/CibaTests.cs), [TwoReplicaSmokeTests.cs](../../src/tests/TwoReplicaSmokeTests.cs).

### B9

Existing conformance documentation accepts the server error-page review path. Retain the owner-directed deferral; do not treat it as an urgent protocol failure.

[README.md](../../conformance/README.md), [202611030100-conformance-healthcheck-dependabot-locks.md](../activities/202611030100-conformance-healthcheck-dependabot-locks.md).

### C1

Re-wrap, loss and key leases are covered separately. They do not prove the mixed re-wrap/data-key rotation race or production authority separation.

[VaultTests.KekRewrap.cs](../../src/tests/VaultTests.KekRewrap.cs), [VaultSymmetricKeyLeaseTests.cs](../../src/tests/VaultSymmetricKeyLeaseTests.cs), [202610231900-vault-kek-escrow.md](../activities/202610231900-vault-kek-escrow.md).

### C2

Purpose-separated token certificates and overlap were delivered. Retain provider lifecycle, cross-purpose rehearsal and dated retirement gates, rather than recreating separation.

[IdentityCertificateMaterial.cs](../../src/sts/IdentityCertificateMaterial.cs), [CertificatesOptions.cs](../../src/sts/Options/CertificatesOptions.cs), [202610231600-encryption-certificate-separation.md](../activities/202610231600-encryption-certificate-separation.md).

### C4

Transport policy and its tests exist; the last recorded deployment choice must be checked at execution. No live connection strings were read for this review.

[DatabaseTransportPolicyTests.cs](../../src/tests/DatabaseTransportPolicyTests.cs), [202610231500-plan-reassessment.md](../activities/202610231500-plan-reassessment.md).

### C5

An inventory/rotation completion artifact is still required; absence of one is not proof credentials are compromised or still unchanged.

[RUNBOOK-PRODUCTION-EVIDENCE.md](../runbooks/RUNBOOK-PRODUCTION-EVIDENCE.md).

### D1

AcknowledgeReportOnly remains a boolean without an expiry. Existing CSP tests do not bound that exception lifetime.

[HttpSurfaceOptions.cs](../../src/sts/Options/HttpSurfaceOptions.cs), [CspHeaderTests.cs](../../src/tests/CspHeaderTests.cs).

### E2

Rotation, overlap/revocation, one-time display and metadata-only lists exist. Rotation currently uses ClientsUpdate, not its own capability. Vault provenance in the UI and safe cloning remain.

[ClientEdit.razor](../../src/ui/Sufficit.Identity.UI.Management/Components/Pages/ClientEdit.razor), [ClientManagementService.Mutations.Lifecycle.cs](../../src/management/Clients/ClientManagementService.Mutations.Lifecycle.cs), [ClientsControllerTests.Credentials.cs](../../src/tests/ClientsControllerTests.Credentials.cs), [USAGE-MANAGED-CLIENT-CREDENTIALS.md](../usage/USAGE-MANAGED-CLIENT-CREDENTIALS.md).

### E3

Client-filtered metrics and links to filtered session/authorization revocation already exist. The audit backend now filters resources, but Audit.razor still uses the newest-event list.

[Metrics.razor](../../src/ui/Sufficit.Identity.UI.Management/Components/Pages/Metrics.razor), [MetricsManagementService.cs](../../src/management/Metrics/MetricsManagementService.cs), [ClientDetail.razor](../../src/ui/Sufficit.Identity.UI.Management/Components/Pages/ClientDetail.razor), [SessionsAndAuthorizationsControllerTests.cs](../../src/tests/SessionsAndAuthorizationsControllerTests.cs), [USAGE-AUDIT-HISTORY.md](../management/USAGE-AUDIT-HISTORY.md).

### E4

The management contract exposes lifetimes, PAR and authentication settings, not the requested complete typed metadata/claim extension model. Existing claim-release policy must be reused.

[ClientManagementContracts.cs](../../src/application/Sufficit.Identity.Application.Abstractions/Management/Clients/ClientManagementContracts.cs), [TokenIssuancePolicies.cs](../../src/sts/TokenIssuancePolicies.cs), [ClientDefinitionPolicyTests.cs](../../src/tests/ClientDefinitionPolicyTests.cs).

### E6

Page overflow and drawer tab order already have responsive coverage; this is not evidence for all create/edit interactions, real virtual keyboards or concurrent editing.

[ManagementConsoleResponsiveTests.cs](../../src/tests/Sufficit.Identity.BrowserTests/ManagementConsoleResponsiveTests.cs), [202610282200-plan-closed-sections.md](../activities/202610282200-plan-closed-sections.md).

### E7

Module registry/version validation is implemented. The requested semantic endpoint contract, standalone BFF/public interaction protocol and third-party kit are not established by these artifacts.

[UiModuleRegistry.cs](../../src/ui/Sufficit.Identity.UI.Abstractions/Hosting/UiModuleRegistry.cs), [UiModuleRegistryTests.cs](../../src/tests/UiModuleRegistryTests.cs), [USAGE-EMBEDDED-UI.md](../usage/USAGE-EMBEDDED-UI.md).

### E8

Responsive and keyboard checks are partial evidence, not a completed WCAG 2.2 AA audit of both UIs.

[ManagementConsoleResponsiveTests.cs](../../src/tests/Sufficit.Identity.BrowserTests/ManagementConsoleResponsiveTests.cs).

### F1

IProtocolFeature has configuration/discovery hooks but no posture contributor hook; findings remain separately composed.

[ProtocolFeature.cs](../../src/sts/Features/ProtocolFeature.cs), [StsProductionPostureContributor.cs](../../src/sts/Security/StsProductionPostureContributor.cs).

### F2

The shared guard exists; operation wrappers remain repeated and both ManagementOptions definitions still exist.

[ManagementOperationGuard.cs](../../src/management/Audit/ManagementOperationGuard.cs), [ManagementOptions.cs](../../src/sts/Options/ManagementOptions.cs), [ManagementOptions.cs](../../src/application/Sufficit.Identity.Application.Abstractions/Management/ManagementOptions.cs).

### F3

Equality/member-path regex parsing and private PATCH helpers remain. Sorting is not advertised; no shared AST/filter repository implementation was found.

[ScimProvisioningService.Support.cs](../../src/scim/ScimProvisioningService.Support.cs), [ScimProvisioningService.cs](../../src/scim/ScimProvisioningService.cs), [ScimDiscoveryController.cs](../../src/scim/ScimDiscoveryController.cs), [ScimProvisioningTests.cs](../../src/tests/ScimProvisioningTests.cs).

### F4

Distributed ticket cache, timeout fallback, invalidation and opt-in stamp caching already exist. ITicketStore paths still pass CancellationToken.None; repository/cancellation and combined fault coverage remain.

[OidcUserSessionTicketStore.cs](../../src/sts/OidcUserSessionTicketStore.cs), [SessionValidity.cs](../../src/core/Sessions/SessionValidity.cs), [ServerSideSessionsTests.cs](../../src/tests/ServerSideSessionsTests.cs), [SessionValidityCacheIntegrationTests.cs](../../src/tests/SessionValidityCacheIntegrationTests.cs), [ARCHITECTURE-SESSION-VALIDITY.md](../architecture/ARCHITECTURE-SESSION-VALIDITY.md).

### F5

Production HTTP startup already rejects AutoMigrate; only migrate-only or Development applies schema changes. Canonical/additive tests exist, but not the full two-replica failure/retry/old-binary scenario.

[HostBootstrap.Schema.cs](../../src/server/HostBootstrap.Schema.cs), [MariaDbMigrationIntegrationTests.cs](../../src/tests/MariaDbMigrationIntegrationTests.cs).

### F6

The fork/local feed and checksum gate remain. CI already audits dependency vulnerabilities; reproducible fork provenance, license coverage and upstream compatibility still need evidence.

[Directory.Packages.props](../../Directory.Packages.props), [ci.yml](../../.github/workflows/ci.yml).

### F7

The committed database lane remains MariaDB 10.4.34. No dual-version cutover/restore completion evidence was found; choose a supported target at execution time.

[ci.yml](../../.github/workflows/ci.yml), [MariaDbMigrationIntegrationTests.cs](../../src/tests/MariaDbMigrationIntegrationTests.cs).

### F9

Unique lookup and duplicate-email rejection tests exist; a multi-entry-point concurrency matrix is still needed and is shared with F15.

[AccountLookupPolicyTests.cs](../../src/tests/AccountLookupPolicyTests.cs), [108-unique-normalized-email.sql](../migration/sql/108-unique-normalized-email.sql).

### F10

RegistrationController exposes POST creation, not the protected DCR lifecycle. Caller-supplied secrets remain an opt-in; a migration deadline/audited adapter is not provided by the default-off flag.

[RegistrationController.cs](../../src/sts/Controllers/RegistrationController.cs), [McpOptions.cs](../../src/sts/Options/McpOptions.cs).

### F11

Failure modes are implemented; changing the deployed mode requires current availability/latency evidence. The old LocalFallback record is historical.

[BreachedPasswordValidator.cs](../../src/sts/BreachedPasswordValidator.cs), [202609201700-breached-password-fallback.md](../activities/202609201700-breached-password-fallback.md).

### F12

Local ConcurrentDictionary counts and metrics export exist; a restart-safe, replica-aggregate budget authority and automated rotation are still absent.

[VaultCryptographyTelemetry.cs](../../src/vault/VaultCryptographyTelemetry.cs), [VaultCryptographyTelemetryTests.cs](../../src/tests/VaultCryptographyTelemetryTests.cs).

### F14

Code comments still mix historical design narratives with current behavior. Audit targeted security assertions against composition and executable tests; do not bulk-delete useful rationale.

[OidcUserSessionTicketStore.cs](../../src/sts/OidcUserSessionTicketStore.cs), [ProtocolFeature.cs](../../src/sts/Features/ProtocolFeature.cs).

### F15

Only the design exists: current lookup uses users.Email and UpdateProfile uses SetEmailAsync. No useremails migration/service/routes were found; 110 is a proposed number, not a reserved allocation.

[ARCHITECTURE-ACCOUNT-EMAILS.md](../architecture/ARCHITECTURE-ACCOUNT-EMAILS.md), [AccountLookupPolicy.cs](../../src/sts/AccountLookupPolicy.cs), [UserManagementService.Profile.cs](../../src/management/Users/UserManagementService.Profile.cs), [109-add-token-maintenance.sql](../migration/sql/109-add-token-maintenance.sql).

### G1

Decision logging, retention/access control and profile audit search exist. They do not implement durable outbox delivery, complete event coverage or operational alerts.

[ManagementAuditService.cs](../../src/management/Audit/ManagementAuditService.cs), [ManagementOperationGuard.cs](../../src/management/Audit/ManagementOperationGuard.cs), [TokenIssuancePolicies.cs](../../src/sts/TokenIssuancePolicies.cs), [USAGE-AUDIT-HISTORY.md](../management/USAGE-AUDIT-HISTORY.md).

### G2

OIDC/FAPI automation is documented. This does not prove SSF suite execution, formal certification or independent review; external engagements remain operational.

[README.md](../../conformance/README.md), [conformance.yml](../../.github/workflows/conformance.yml).

### G3

Replica replay/nonce/passkey/CIBA tests, feature-off tests, MariaDB rehearsals and production revocation evidence already exist. Build a remaining browser/Redis/fault matrix instead of redoing them.

[TwoReplicaSmokeTests.cs](../../src/tests/TwoReplicaSmokeTests.cs), [MariaDbMigrationIntegrationTests.cs](../../src/tests/MariaDbMigrationIntegrationTests.cs), [CibaTests.cs](../../src/tests/CibaTests.cs), [ManagementConsoleResponsiveTests.cs](../../src/tests/Sufficit.Identity.BrowserTests/ManagementConsoleResponsiveTests.cs), [202610281700-replica-revocation.md](../activities/202610281700-replica-revocation.md).

### G4

Forwarded-origin/proxy verification has dated end-to-end evidence. Encryption overlap and token revocation are not equivalent to signing JWKS rotation or a complete client inventory.

[202610222030-credential-abuse-protection.md](../activities/202610222030-credential-abuse-protection.md), [202610231600-encryption-certificate-separation.md](../activities/202610231600-encryption-certificate-separation.md), [202610281700-replica-revocation.md](../activities/202610281700-replica-revocation.md).

### G5

Unused-account purge is implemented. Treatment of used-but-unconfirmed accounts remains a decision based on a fresh inventory, not on historical account counts.

[UnconfirmedAccountPurgeWorker.cs](../../src/management/Users/UnconfirmedAccountPurgeWorker.cs), [202610231500-plan-reassessment.md](../activities/202610231500-plan-reassessment.md).

### G6

These remain optional roadmap work. Existing SSF dispatch is not a durable outbox; keep it distinct from administrative audit delivery.

[README.md](../../conformance/README.md), [SharedSignalsDispatcher.cs](../../src/sts/SharedSignals/SharedSignalsDispatcher.cs).

### G7

Disclosure is an external owner decision. Keep confidential identifiers and reproduction details out of the public review record.

[RUNBOOK-PRODUCTION-EVIDENCE.md](../runbooks/RUNBOOK-PRODUCTION-EVIDENCE.md).

## Original item disposition

Each item ID is its old section plus original checkbox ordinal. The original
wording is retained for traceability; it may contain claims corrected in the
focused plan. The destination contains the updated scope.

| ID | Original item | Disposition | Destination / evidence section |
|---|---|---|---|
| A2.1 | **(operational, ~2026-11-04)** Reconcile the observed denials (audit `reasonCode like 'scope_grant_%'`, `operationOutcome = 'observed'`), then set `ClientScopeGrants:Mode=Enforce` on the three nodes | operational | [A2](../plans/PLAN-AUTHORIZATION.md); evidence A2 above |
| A2.2 | **(operational, before 2027-04-30)** Migrate plaintext-secret callers (`client_secret_plaintext_deprecated`) to `secretReference` and remove the adapter after `ClientSecrets:PlaintextExpiresAtUtc` | operational | [A2](../plans/PLAN-AUTHORIZATION.md); evidence A2 above |
| A2.3 | **(operational)** Inventory the real production manifests and adopt existing managed clients explicitly before enabling client-definition enforcement | operational | [A2](../plans/PLAN-AUTHORIZATION.md); evidence A2 above |
| A2.4 | Bring `/secret/rotate` and `/credentials` onto `secretReference`; they still accept an operator-supplied secret | pending | [A2](../plans/PLAN-AUTHORIZATION.md); evidence A2 above |
| A3.1 | **(operational, gated: SCIM is off in production)** Inventory the provisioning clients, grant `scim.destructive` to the ones that legitimately delete or reset passwords, bind their tokens, then set `Scim:OperationPolicyMode=Enforce` | operational | [A3](../plans/PLAN-SCIM.md); evidence A3 above |
| A4.1 | Finish the single evidence policy. Neither side is unified yet: SCIM keeps its own reader (`ScimServiceCollectionExtensions.cs`, own method set and `HasMfaEvidence`) beside `MfaEvidencePolicy`, and `amr` is still set in several places (interactive sign-in, identity-assertion grants, provisioning and operator tokens, development endpoints) | partial | [A4](../plans/PLAN-AUTHORIZATION.md); evidence A4 above |
| A4.2 | End-to-end tests proving a real MFA login satisfies Management and SCIM policies, and that a stale session cannot mutate credentials | partial | [A4](../plans/PLAN-AUTHORIZATION.md); evidence A4 above |
| B3.1 | Let the holder of a DPoP-bound subject token exchange it. It fails closed today: `ValidateDpopAccessTokenProof` checks `ath` against the reference token's resolved payload (`context.Token`) because the token endpoint has no `AccessToken`, so even the right key and a correct `ath` are refused; once fixed, the same proof is checked again in `TokenGrantDispatcher` and its replay guard may refuse it. Pinned by the skipped test in `TokenExchangeSubjectTokenTests`. No production exchange presents a DPoP-bound subject token today | pending | [B3](../plans/PLAN-PROTOCOL-ASSURANCE.md); evidence B3 above |
| B5.1 | Run CIBA interoperability/conformance and approval-fatigue abuse tests before enabling additional clients | partial | [B5](../plans/PLAN-PROTOCOL-ASSURANCE.md); evidence B5 above |
| B9.1 | Resolve the client's registered redirect URI before the refusal, and only when the registration leaves no ambiguity — **revisit only if a client ever needs the machine-readable error.** No authorization is granted and the user is told either way. | deferred | [B9](../plans/PLAN-PROTOCOL-ASSURANCE.md); evidence B9 above |
| C1.1 | **(operational)** Separate database-reader authority from KEK authority in production | operational | [C1](../plans/PLAN-KEYS-VAULT.md); evidence C1 above |
| C1.2 | Test a re-wrap racing a data-key rotation on another replica (loss, old-version decrypt and restore are covered: [`202610232000`](../activities/202610232000-vault-kek-rotation.md)) | pending | [C1](../plans/PLAN-KEYS-VAULT.md); evidence C1 above |
| C2.1 | **(operational, from 2026-11-20)** Drop `certificate.pfx` and `certificate-old.pfx` from `EncryptionPaths`: the last valid token encrypted with them expires 2026-11-19 17:39 UTC | operational | [C2](../plans/PLAN-KEYS-VAULT.md); evidence C2 above |
| C2.2 | Introduce purpose-separated protocol signing/encryption keys with active/retiring overlap, stable `kid`, JWKS rotation and a KMS/HSM-backed production provider | partial | [C2](../plans/PLAN-KEYS-VAULT.md); evidence C2 above |
| C2.3 | Separate token, Data Protection and TLS key material; validate the compromise and rollback procedures | partial | [C2](../plans/PLAN-KEYS-VAULT.md); evidence C2 above |
| C2.4 | **(operational)** Audit and rotate any production signing material that may have been created through the legacy helper path, recording only thumbprints and versions — never keys or passwords | operational | [C2](../plans/PLAN-KEYS-VAULT.md); evidence C2 above |
| C2.5 | **(operational)** Inventory certificates, prove the signing/KEK separation and execute a restore/disaster-recovery rehearsal | operational | [C2](../plans/PLAN-KEYS-VAULT.md); evidence C2 above |
| C4.1 | **(operational)** Select `RequireVerifiedTls` — or the audited `PrivateSocket` exception — in each production deployment, after the CA or socket is provisioned. Today the connection string declares no `SslMode` and goes through the local proxy (`db-proxy-local`) | operational | [C4](../plans/PLAN-PRODUCTION-GATES.md); evidence C4 above |
| C5.1 | Inventory and rotate the legacy database and provider credentials and certificates, migrate `deploy/local/` to the approved secret store, and attach a redacted manifest with owner, version, state and retirement date | operational | [C5](../plans/PLAN-PRODUCTION-GATES.md); evidence C5 above |
| D1.1 | Make the report-only rollback switch bounded: `AcknowledgeReportOnly` has no expiry (reports already strip query and userinfo) | pending | [D1](../plans/PLAN-AUTHORIZATION.md); evidence D1 above |
| E2.1 | Integrate `SecretReference` and the vault into the console's credential surface | partial | [E2](../plans/PLAN-CLIENT-CONSOLE.md); evidence E2 above |
| E2.2 | Explicit rotation behind its own capability | partial | [E2](../plans/PLAN-CLIENT-CONSOLE.md); evidence E2 above |
| E2.3 | Show only "credential configured", its origin and a safe date — never the value or a hint derived from it | partial | [E2](../plans/PLAN-CLIENT-CONSOLE.md); evidence E2 above |
| E2.4 | Cloning that copies no secret, token, authorization or operational state | pending | [E2](../plans/PLAN-CLIENT-CONSOLE.md); evidence E2 above |
| E2.5 | Confirm impact and revoke authorizations/tokens only when the policy requires it | partial | [E2](../plans/PLAN-CLIENT-CONSOLE.md); evidence E2 above |
| E2.6 | Document rollback and recovery | partial | [E2](../plans/PLAN-CLIENT-CONSOLE.md); evidence E2 above |
| E2.7 | Define typed application claims and properties with an allow-list and destinations | merged | [E4.2](../plans/PLAN-CLIENT-CONSOLE.md); evidence E2 above |
| E3.1 | Per-application metrics connected to the existing metrics module | closed | [E3](../plans/PLAN-CLIENT-CONSOLE.md); evidence E3 above |
| E3.2 | Audit timeline filtered by client ID | partial | [E3](../plans/PLAN-CLIENT-CONSOLE.md); evidence E3 above |
| E3.3 | Session and authorization revocation actions in the application's context | closed | [E3](../plans/PLAN-CLIENT-CONSOLE.md); evidence E3 above |
| E3.4 | Volume test with thousands of clients | pending | [E3](../plans/PLAN-CLIENT-CONSOLE.md); evidence E3 above |
| E4.1 | Typed public metadata (`description`, `client_uri`, `logo_uri`) | pending | [E4](../plans/PLAN-CLIENT-CONSOLE.md); evidence E4 above |
| E4.2 | Application claims with allow-list and destinations, through a release policy that sees client, grant, scopes, resources and destination and is shared by the grants and the privileged mints ([`202610240200`](../activities/202610240200-no-unified-issuance-service.md)) | pending | [E4](../plans/PLAN-CLIENT-CONSOLE.md); evidence E4 above |
| E4.3 | Advanced properties with a namespace and reserved keys | pending | [E4](../plans/PLAN-CLIENT-CONSOLE.md); evidence E4 above |
| E4.4 | Per-client DPoP/JAR/CIBA/FAPI configuration only where the runtime actually honours it | partial | [E4](../plans/PLAN-CLIENT-CONSOLE.md); evidence E4 above |
| E4.5 | New profiles only when each has a validator, an explanation and tests | guardrail | [E4](../plans/PLAN-CLIENT-CONSOLE.md); evidence E4 above |
| E6.1 | Deliver and test the client configurator at 320–430 px first, then tablet and desktop | partial | [E6](../plans/PLAN-CLIENT-CONSOLE.md); evidence E6 above |
| E6.2 | Validate keyboard, focus, virtual keyboard, deep link, F5 and concurrency on the creation and edit flows | pending | [E6](../plans/PLAN-CLIENT-CONSOLE.md); evidence E6 above |
| E6.3 | **(operational)** Publish the update capability per deployment and validate the real clients | operational | [E6](../plans/PLAN-CLIENT-CONSOLE.md); evidence E6 above |
| E7.1 | **Phase 2:** semantic endpoint registration (module-declared routes rather than hard-coded paths); an official standalone embedded-composition executable, not just the API host | pending | [E7](../plans/PLAN-UI-COMPOSITION.md); evidence E7 above |
| E7.2 | **Phase 3 — remote Management UI:** publish the complete versioned Management HTTP contract (BFF API spec); a standalone BFF host with code flow, PKCE and server-side tokens; end-to-end authorization/CSRF/logout/ token-leakage tests | pending | [E7](../plans/PLAN-UI-COMPOSITION.md); evidence E7 above |
| E7.3 | **Phase 4 — remote public interaction:** specify and threat-model the opaque interaction protocol (login, consent, device, logout); durable distributed interaction state with replay protection; replace hard-coded UI redirects with semantic endpoint resolution; end-to-end coverage of login, external, MFA, passkeys, consent, logout, device and registration | pending | [E7](../plans/PLAN-UI-COMPOSITION.md); evidence E7 above |
| E7.4 | **Phase 5 — third-party SDK:** templates, examples, packages and a compatibility policy; a conformance kit published and run in CI; documented trusted-package approval and remote-provider registration | pending | [E7](../plans/PLAN-UI-COMPOSITION.md); evidence E7 above |
| E8.1 | WCAG 2.2 AA accessibility audit of both embedded UIs | pending | [E8](../plans/PLAN-CLIENT-CONSOLE.md); evidence E8 above |
| F1.1 | Add the posture contributor to the feature contract, so a feature owns its production findings the same way it owns its discovery metadata (today the findings live in four separate `IProductionPostureContributor` implementations, one of which carries every STS finding regardless of which feature owns the setting — which is how the coverage fell behind the configuration surface in the first place) | pending | [F1](../plans/PLAN-RUNTIME-ARCHITECTURE.md); evidence F1 above |
| F2.1 | Replace the `DemandAsync`/`TryWriteAuditAsync` pair repeated across about thirty management files with a `ManagementOperationExecutor` | pending | [F2](../plans/PLAN-RUNTIME-ARCHITECTURE.md); evidence F2 above |
| F2.2 | Remove the duplicated `ManagementOptions` (STS × Abstractions) | pending | [F2](../plans/PLAN-RUNTIME-ARCHITECTURE.md); evidence F2 above |
| F3.1 | Extract `IScimFilterParser` and a typed filter AST from `ScimProvisioningService`; translate only validated nodes to parameterized LINQ. Filtering is two regexes today — `EqualityFilterRegex` and `MemberPathFilterRegex` — so equality is all a caller gets | pending | [F3](../plans/PLAN-SCIM.md); evidence F3 above |
| F3.2 | Add `co`, `sw`, `ew`, logical composition and the multi-valued email/member filters current consumers need | pending | [F3](../plans/PLAN-SCIM.md); evidence F3 above |
| F3.3 | Extract the repositories and promote the PATCH applicator to a shared one; `NormalizePatchOperation`/`ValidatePatchRequest` are private statics in `ScimProvisioningService.Support.cs`. The service is already split into `.Users`, `.Groups` and `.Support` | pending | [F3](../plans/PLAN-SCIM.md); evidence F3 above |
| F3.4 | Add bulk, sorting and ETags — intentionally unadvertised today; enable per demand, from this same extraction rather than a parallel contract | pending | [F3](../plans/PLAN-SCIM.md); evidence F3 above |
| F3.5 | Tests: resource limits, parser timeout, invalid filter, MariaDB translation, interoperability | pending | [F3](../plans/PLAN-SCIM.md); evidence F3 above |
| F4.1 | Introduce a cancellation-aware session repository with a shared cache and explicit revocation invalidation. `OidcUserSessionTicketStore` already gates the activity write behind an interval, so the unbounded per-request write is gone; the repository, the shared cache and the cancellation contract are not | partial | [F4](../plans/PLAN-RUNTIME-ARCHITECTURE.md); evidence F4 above |
| F4.2 | Define database/cache outage behaviour so a temporary storage failure neither creates an unbounded login outage nor accepts revoked sessions indefinitely | partial | [F4](../plans/PLAN-RUNTIME-ARCHITECTURE.md); evidence F4 above |
| F4.3 | Multi-replica consistency, stale-cache, failover and cancellation tests | partial | [F4](../plans/PLAN-RUNTIME-ARCHITECTURE.md); evidence F4 above |
| F5.1 | Remove the web process's migration responsibility now that deployment automation has the migrator. `AutoMigrate` already defaults to `false`, and `AllowedDatabaseNames` guards it, so this is about deleting the path rather than turning a switch | closed | [F5](../plans/PLAN-RUNTIME-ARCHITECTURE.md); evidence F5 above |
| F5.2 | Test two-replica startup, failed migration, retry and old-binary rollback against additive schema | partial | [F5](../plans/PLAN-RUNTIME-ARCHITECTURE.md); evidence F5 above |
| F6.1 | Validate the upstream EF Core 10 provider against the canonical MariaDB schema, migrations, concurrency behaviour and connection-pool settings | pending | [F6](../plans/PLAN-DATABASE-PROVIDER.md); evidence F6 above |
| F6.2 | Run the upstream provider in CI and in a production-shaped canary before changing the central package source | pending | [F6](../plans/PLAN-DATABASE-PROVIDER.md); evidence F6 above |
| F6.3 | Remove `.nuget-feed` and the fork-integrity step only after provenance, migration output and runtime behaviour match | pending | [F6](../plans/PLAN-DATABASE-PROVIDER.md); evidence F6 above |
| F6.4 | If the fork has to remain, publish it under a Sufficit-owned package ID with repository URL, commit, license, deterministic-build and SBOM metadata, build it in CI from a pinned commit and compare the produced artifact hash — the checksum of an opaque committed package is not provenance | pending | [F6](../plans/PLAN-DATABASE-PROVIDER.md); evidence F6 above |
| F6.5 | Run vulnerability and license scanning against the source and the final dependency graph | partial | [F6](../plans/PLAN-DATABASE-PROVIDER.md); evidence F6 above |
| F7.1 | Select a currently supported MariaDB LTS target compatible with the provider | pending | [F7](../plans/PLAN-DATABASE-PROVIDER.md); evidence F7 above |
| F7.2 | Run both versions in CI: canonical schema, additive rehearsal, grants, concurrency, locking, collations, index-width behaviour | pending | [F7](../plans/PLAN-DATABASE-PROVIDER.md); evidence F7 above |
| F7.3 | **(operational)** Canary production-shaped traffic, migrate replicas and backups, retain 10.4 compatibility until the cutover completes | operational | [F7](../plans/PLAN-DATABASE-PROVIDER.md); evidence F7 above |
| F7.4 | Remove the 10.4 lane only after rollback and restore rehearsals succeed on the target | pending | [F7](../plans/PLAN-DATABASE-PROVIDER.md); evidence F7 above |
| F9.1 | Add registration, SCIM update, email change, login and recovery race tests | partial | [F9](../plans/PLAN-ACCOUNT-EMAILS.md); evidence F9 above |
| F10.1 | Implement protected read, update, delete, secret rotation and the audit lifecycle | partial | [F10](../plans/PLAN-PROTOCOL-ASSURANCE.md); evidence F10 above |
| F10.2 | Retain caller-supplied secrets only behind a deprecated audited adapter during migration, with an entropy floor and a deadline | partial | [F10](../plans/PLAN-PROTOCOL-ASSURANCE.md); evidence F10 above |
| F10.3 | Align the operator-managed application lifecycle and secret references with E2 | dependency | [F10](../plans/PLAN-PROTOCOL-ASSURANCE.md); evidence F10 above |
| F10.4 | **(decision)** DCR is **on** in production for anonymous public clients (`Dcr:Enabled=true`, `RequireInitialAccessToken=false`, chosen in [`202609132250`](../activities/202609132250-deploy-evaluation-remediation.md)). Either require an initial access token until the lifecycle, abuse controls and interoperability tests are complete, or record the accepted risk | decision | [F10](../plans/PLAN-PROTOCOL-ASSURANCE.md); evidence F10 above |
| F11.1 | **(operational)** Move to `FailClosed` once the `breached_password_check` telemetry characterises latency and availability (production runs `LocalFallback`: [`202609201200`](../activities/202609201200-breach-check-in-production.md), [`202609201700`](../activities/202609201700-breached-password-fallback.md)) | operational | [F11](../plans/PLAN-PRODUCTION-GATES.md); evidence F11 above |
| F12.1 | Auto-rotate the DEK at its budget, or drive rotation from a durable counter. `VaultCryptographyTelemetry` warns at 80% and logs critical at 100%, but it counts **per process** in a `ConcurrentDictionary`, so three replicas reach the real budget while each reports a third of it. Automatic rotation is disabled on purpose until the aggregated metric exists | pending | [F12](../plans/PLAN-KEYS-VAULT.md); evidence F12 above |
| F14.1 | Remove comments claiming a guard is unconditional where composition makes it conditional | pending | [F14](../plans/PLAN-RUNTIME-ARCHITECTURE.md); evidence F14 above |
| F14.2 | Review security comments against executable tests and delete the historical "item fixed" narratives that no longer describe current behaviour | pending | [F14](../plans/PLAN-RUNTIME-ARCHITECTURE.md); evidence F14 above |
| F15.1 | Migration 110 `useremails` (primary mirrored as a row, unique normalized address) with backfill from `users.Email` | pending | [F15](../plans/PLAN-ACCOUNT-EMAILS.md); evidence F15 above |
| F15.2 | `IAccountEmailService` as the only writer; dual-write `users.Email`; `UpdateProfile` email change routed through it | pending | [F15](../plans/PLAN-ACCOUNT-EMAILS.md); evidence F15 above |
| F15.3 | Parity check between `users.Email` and the primary row as a posture finding | pending | [F15](../plans/PLAN-ACCOUNT-EMAILS.md); evidence F15 above |
| F15.4 | `AccountLookupPolicy` reads confirmed rows only, behind a flag | pending | [F15](../plans/PLAN-ACCOUNT-EMAILS.md); evidence F15 above |
| F15.5 | Management routes under `api/users/{id}/emails` (`identity.users.update`) and console page | pending | [F15](../plans/PLAN-ACCOUNT-EMAILS.md); evidence F15 above |
| F15.6 | Self-service `/manage/emails` with confirmation link, recent authentication and notification of the previous primary | pending | [F15](../plans/PLAN-ACCOUNT-EMAILS.md); evidence F15 above |
| F15.7 | SCIM full `emails[]` mapping per client trust | pending | [F15](../plans/PLAN-ACCOUNT-EMAILS.md); evidence F15 above |
| F15.8 | Race and non-resolution tests listed in the design (extends F9) | dependency | [F15](../plans/PLAN-ACCOUNT-EMAILS.md); evidence F15 above |
| G1.1 | Emit structured, PII-safe events for issuance policy, actor chain, personal tokens, step-up, replay, egress denial, key rotation and authorization denial | partial | [G1](../plans/PLAN-OBSERVABILITY-CONFORMANCE.md); evidence G1 above |
| G1.2 | Deliver the security audit through a durable outbox, with a defined retention, integrity and access-control policy | partial | [G1](../plans/PLAN-OBSERVABILITY-CONFORMANCE.md); evidence G1 above |
| G1.3 | Alert on compatibility fallback, plaintext/TLS warnings, replay pressure, unexpected public origin and expiring keys | pending | [G1](../plans/PLAN-OBSERVABILITY-CONFORMANCE.md); evidence G1 above |
| G2.1 | Run the SSF conformance suite for the capabilities announced | pending | [G2](../plans/PLAN-OBSERVABILITY-CONFORMANCE.md); evidence G2 above |
| G2.2 | **(operational)** Submit the applicable profiles to formal certification | operational | [G2](../plans/PLAN-OBSERVABILITY-CONFORMANCE.md); evidence G2 above |
| G2.3 | **(operational)** Commission an external audit of DPoP, CIBA, JARM, JAR, mTLS, token exchange, SSF and the vault; fix and retest every blocking finding | operational | [G2](../plans/PLAN-OBSERVABILITY-CONFORMANCE.md); evidence G2 above |
| G2.4 | **(operational)** Commission an independent review of the custom protocol/security code | operational | [G2](../plans/PLAN-OBSERVABILITY-CONFORMANCE.md); evidence G2 above |
| G3.1 | Browser tests for passkey registration/login, 2FA, consent, CSP and step-up on the supported desktop and mobile engines | partial | [G3](../plans/PLAN-OBSERVABILITY-CONFORMANCE.md); evidence G3 above |
| G3.2 | Real MariaDB/Redis concurrency tests, feature-off 404 tests, host-poisoning tests and key/cache/database fault injection | partial | [G3](../plans/PLAN-OBSERVABILITY-CONFORMANCE.md); evidence G3 above |
| G3.3 | **(operational)** Verify the egress firewall and every approved outbound target in the production topology | operational | [G3](../plans/PLAN-OBSERVABILITY-CONFORMANCE.md); evidence G3 above |
| G4.1 | Every active client has an assigned owner and a documented final state | operational | [G4](../plans/PLAN-PRODUCTION-GATES.md); evidence G4 above |
| G4.2 | Confidential clients have newly issued, post-migration credentials | operational | [G4](../plans/PLAN-PRODUCTION-GATES.md); evidence G4 above |
| G4.3 | Redirect, logout and CORS allow-lists verified per client | operational | [G4](../plans/PLAN-PRODUCTION-GATES.md); evidence G4 above |
| G4.4 | Token format validated by every resource server (reference vs JWT) | operational | [G4](../plans/PLAN-PRODUCTION-GATES.md); evidence G4 above |
| G4.5 | JWKS overlap and rotation tested — old and new keys visible during the transition | partial | [G4](../plans/PLAN-PRODUCTION-GATES.md); evidence G4 above |
| G4.6 | Proxy and forwarded headers verified end to end (`X-Forwarded-Proto`/`Host`, TrustedProxies) | closed | [G4](../plans/PLAN-PRODUCTION-GATES.md); evidence G4 above |
| G5.1 | Decide on the accounts with an unconfirmed email that **were** used (a token in the last 90 days): confirm them in bulk or leave them to reconfirmation — the unused ones are purged automatically | decision | [G5](../plans/PLAN-ACCOUNT-EMAILS.md); evidence G5 above |
| G6.1 | FAPI 2.0 Advancing Profile (needs encrypted request objects beyond JAR) | deferred | [G6](../plans/PLAN-PROTOCOL-ROADMAP.md); evidence G6 above |
| G6.2 | Rich Authorization Requests (RAR — `authorization_details`) | deferred | [G6](../plans/PLAN-PROTOCOL-ROADMAP.md); evidence G6 above |
| G6.3 | OpenID Federation (entity statements, trust chains) | deferred | [G6](../plans/PLAN-PROTOCOL-ROADMAP.md); evidence G6 above |
| G6.4 | SSF durable outbox/retry state (persistent delivery guarantees beyond best-effort) | deferred | [G6](../plans/PLAN-PROTOCOL-ROADMAP.md); evidence G6 above |
| G7.1 | Decide on coordinated disclosure before adding the confidential review identifier or any reproduction detail to this public repository | operational | [G7](../plans/PLAN-PRODUCTION-GATES.md); evidence G7 above |

## Closure criteria and calendar preservation

CR1–CR7 are retained verbatim in the index as shared closure gates, not claimed
completed by this review. CAL1–CAL7 are retained in their original order in
[Production gates](../plans/PLAN-PRODUCTION-GATES.md): disabled legacy IDs,
scope-grant enforcement, compatibility removal, encryption-path retirement,
legacy bridge scope, plaintext-secret callers and manifest adoption.

## Validation and delivery

- Existing compiled focused suite: **93 passed, zero warnings** using
  `dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-build --no-restore`
  with filters for MetricsManagementTests, SessionsAndAuthorizationsControllerTests,
  ServerSideSessionsTests, SessionValidityCache*, ClientsControllerTests,
  AccountLookupPolicyTests, TwoReplicaSmokeTests, CredentialMutationSecurityTests
  and ManagementAuditSearchTests. These are in-process/SQLite checks, not a new
  real MariaDB/Redis/browser/production rehearsal.
- Inventory validation passed: 105 dispositions, 99 uniquely owned remaining
  items, 37 unchanged historical headings, 12 focused plans, seven identical
  closure criteria and seven preserved calendar rows. All focused-plan links resolve.
- MarkdownCoverageTests: **8 passed, zero warnings** after restoring a natural
  index link to RUNBOOK-FIRST-PARTY-USER-SCOPES (the first pass found it orphaned
  when old indirect navigation was removed). `git diff --check` passed.
- Checks used read-only source/test inspection; current production state and
  full protocol/browser/real-infrastructure suites were not revalidated.
- Commit/push target: main per owner policy. No runtime implementation or deployment.
