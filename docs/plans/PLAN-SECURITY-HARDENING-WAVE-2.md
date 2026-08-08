# Security hardening — compatibility rollout wave 2

> **Status:** ACTIVE. Reconciled against `79e0f82ac5a9346378de7f92dd37acceace0a875` on 2026-08-07.
>
> **Disclosure note:** this repository is public. This plan records implementation work and acceptance criteria, but intentionally omits the confidential review identifier, reproduction steps, payloads, and exploitation scenarios. Those details remain in the restricted security-review channel until coordinated disclosure.

Code-level controls delivered after this reconciliation are recorded in
`docs/activities/202608071330-completed-security-hardening-wave-2.md`. This plan
stays active for the remaining cross-entry-point lifecycle work, production
inventories, cohort enforcement, conformance and operational proof.

## Delivery constraint

The STS is already serving production traffic. No grant, endpoint, client type, user flow, or integration may be disabled as a remediation shortcut. Every enforcement change must use the following sequence:

1. add the new abstraction and telemetry without changing the decision;
2. inventory existing clients, subjects, configuration, and traffic that would be affected;
3. provide a compatibility adapter, data backfill, or dual-read path;
4. enable enforcement by bounded client/resource cohort;
5. retain an explicit, audited rollback switch for one release window;
6. remove the compatibility path only after telemetry reaches zero legacy use.

Schema changes are additive. Deployments must remain compatible with rolling upgrades. Security denials must be observable without logging credentials, tokens, authorization codes, proofs, or certificate private material.

## Reconciliation summary

The review evaluated an older source snapshot. The current tree already closes two material items and partially closes several others. The table is a code-derived status summary; documentation was not used to infer implementation state.

| Area | Current state | Current code evidence | Destination |
|---|---|---|---|
| Outbound HTTP destination control | **Resolved** | `SafeHttpHandlerFactory` validates scheme/DNS, blocks unsafe ranges, pins the validated address in `ConnectCallback`, disables redirects/proxy by default, and is registered for human verification, logout, SSF, and metrics clients | Regression-only |
| SSF stream ownership | **Resolved** | `SsfStream.OwnerClientId`, owner-scoped store methods, caller resolution in SSF controllers, and cross-owner tests | Regression-only |
| Provisioned client ownership and privileged permissions | **Partially implemented** | `IClientDefinitionValidator`, `IClientScopeGrantPolicy`, reserved-scope checks, provisioning ownership markers, explicit audited `adoptExisting` reconciliation, sensitive-transition authorization, and Observe-mode audit events are wired into management, provisioning, and DCR; production manifest inventory remains open | P0.1 |
| Local redirect/canonical path validation | **Resolved** | `LowercasePathMiddleware` validates before routing and before writing `Location`; the public UI delegates return URLs to the same `LocalUrlValidator`, including encoded separator handling | Regression-only |
| Signing-certificate prestart boundary | **Resolved in code; rollout pending** | root-owned bootstrap, unprivileged read-only preflight, certificate validation and hardened units are covered by deployment tests; production certificate inventory/rotation remains operational | P0.3 / production runbook |
| CIBA client policy | **Implemented with rollout gate** | initiation and polling share `ICibaClientPolicy`, require confidential authentication/grant permission when enforced, bind the pending client and emit PII-free decision telemetry | P0.4 inventory/conformance |
| Personal token issuance policy | **Implemented with rollout gate** | `IPersonalTokenIssuancePolicy` attenuates scopes, checks required scope, client eligibility, authentication age, lifetime and optional sender constraint; Observe remains the compatibility default | P0.5 enforcement |
| Management grant/permission parsing | **Implemented with allow-list** | `ClientManagementService.NormalizeGrantTypes` now maps supported grants explicitly and rejects unknown values before descriptor creation | P0.1 shared validator |
| SCIM client boundary when scope enforcement is relaxed | **Implemented with rollout gate** | `RequireScope` and `RequireAllowedClient` are independent, with an Observe mode and denial audit; production allow-list inventory remains | P0.6 inventory |
| Protected-principal mutations | **Implemented with rollout gate** | capability subset, tier comparison, MFA break-glass and audit decisions are provided by the concrete policy; broad mutation coverage and enforcement rollout remain | P0.7 |
| Object/context authorization | **Implemented with rollout gate** | the concrete policy requires item IDs, resolves legacy/global context and supports Observe/Enforce; data backfill and collection enumeration proof remain | P0.7 / existing GLM plan P0.3 |
| Database-provider provenance | **Partial** | the local provider fork is now isolated by NuGet source mapping and the container restore is locked; package ownership, deterministic fork builds and vulnerability/SBOM evidence remain | P1.8 |
| Custom claim release | **Partial** | sensitive unmapped-claim suppression now emits PII-free decision telemetry; inventory, complete mapping and the fail-closed default remain | P1.1 |
| Token-exchange source-client attribution | **Implemented with rollout gate** | `ISubjectTokenProvenancePolicy` rejects missing, ambiguous or disallowed presenter identity in Enforce mode and records compatibility decisions | P1.2 characterization |
| Unknown/null consent mode | **Resolved at runtime; data cleanup pending** | `AuthorizationConsentPolicy` maps missing/unrecognized legacy metadata to interactive consent, while current management, provisioning, and DCR paths accept only known/default consent modes | P1.3 |
| DPoP nonce partitioning | **Partial; partition implemented** | nonce keys are hashed partitions over endpoint/client/proof key; current/previous overlap and atomic multi-replica proof remain | P1.4 |
| FAPI mTLS client binding | **Implemented with deployment gate** | deployment attestation, per-client SHA-256 certificate pins, chain validation and startup binding checks are implemented; trusted-proxy proof and conformance remain | P1.5 |
| OAuth resource validation | **Implemented with explicit allow-list** | MCP resources are registered as audiences and OpenIddict resource validation remains enabled; dynamic resource onboarding and per-client inventory remain | P1.6 |
| Browser-session `sid` reuse | **Implemented with persistence proof** | reuse now requires the current principal subject to equal the target user and a matching durable session row; missing-row and stale-cookie cases mint a fresh sid | Regression-only |
| Anonymous device-information throttling | **Resolved in code** | a named GET limiter is independent from credential POST limits and has focused burst/enumeration tests | Regression-only |
| Proxy/shared-cache topology guards | **Partial** | explicit deployment topology and startup coherence validation now derive the cache/proxy/issuer contract; production inventory and multi-replica proof remain | P2.1 |
| CSP enforcement | **Partial** | report-only remains the default and inline styles still require UI calibration; the placeholder external image host and websocket wildcards were removed | P2.2 / production-readiness plan |
| Dynamic client registration policy | **Implemented foundation; lifecycle pending** | server-generated IDs/secrets, expiring single-use initial access tokens, central metadata validation and public-client PKCE are covered; update/delete/rotation and broader PKCE policy remain | P1.10 |
| Canonical/additive SQL parity | **Partial** | canonical EF SQL includes current migrations; 082 and the guarded 083 normalized-email script have idempotent CI rehearsal; full legacy replay parity remains | P1.11 |
| Reproducible container restore | **Partial** | Docker restore is locked and the production image is built in CI; pinned fork provenance and dependency scanning remain | P1.8 |
| Production database transport | **Partial** | an explicit transport policy now validates VerifyCA/VerifyFull or a UnixSocket exception; production still needs the mode selected and CA/socket provisioned | P2.3 |
| Email identity uniqueness | **Partial** | recovery, external-login, CIBA and passkey lookup reject ambiguous normalized matches; 083 provides a redacted duplicate report and guarded nullable unique index, while operator cleanup/race coverage remains | P1.12 |
| MariaDB support baseline | **Open** | CI and provider configuration remain fixed to MariaDB 10.4.34 | P2.4 |
| Vault separation and rotation operations | **Partial** | envelope encryption and versioned DEKs now depend on an explicit wrapping-key source abstraction; external KMS/HSM custody and a production rotation orchestrator remain | P2.5 / vault plan |
| Authenticator/recovery secret-at-rest boundary | **Open** | the standard Identity token store persists authenticator/recovery material through `usertokens` without an application encryption adapter | P1.13 |
| Security-critical protocol comments | **Partially reconciled** | The current CIBA route comment now references the OIDC CIBA Core specification and distinguishes RFC 9126/PAR; a repository-wide standards/comment audit remains | P2.6 |
| MariaDB integration-test gating | **Resolved** | missing MariaDB/rehearsal configuration fails tests in CI; real-provider grant and schema tests execute against the service container | Regression-only |

## P0 — close direct authorization and deployment boundaries

### P0.1 Unify client-definition validation and protect provisioned ownership

**Targets:** `OpenIddictManifestProvisioner`, `IdentityProvisioningManifestValidator`, `ClientManagementService`, `RegistrationController`, Application Abstractions.

- [x] Extract an `IClientDefinitionValidator` that receives the actor, source (`management`, `provisioning`, or `dcr`), current descriptor, desired descriptor, and rollout mode
- [x] Replace raw string grant/endpoint/scope permissions with typed value objects and an exhaustive mapping; reject unknown values before an OpenIddict descriptor is built
- [x] Introduce `IReservedScopePolicy` and use it from provisioning, management CRUD, and DCR
- [x] Introduce the companion `IClientScopeGrantPolicy` and use it from provisioning, management CRUD, and DCR
- [x] Persist a provisioning ownership marker containing schema version and manifest identity; existing applications without that marker remain unmanaged
- [x] Require an explicit, audited `adopt` operation before provisioning may mutate an unmanaged existing `client_id`
- [x] Treat confidential-to-public conversion, secret removal, redirect replacement, and privileged-scope expansion as separately authorized transitions
- [x] Add `Observe | Enforce` rollout mode; in Observe, calculate and audit the future denial while preserving the existing request
- [ ] Inventory current manifests and adopt existing managed clients explicitly before enabling enforcement
- [x] Add concurrency/idempotency tests plus negative tests for unmanaged IDs, unknown permissions, protected scopes, and confidential/public transitions

**Implementation checkpoint (2026-08-08):** The shared validator now governs the
three client-definition entry points and rejects unknown grants, disallowed DCR
permissions, reserved scopes, invalid redirect URIs, public
`client_credentials`, and public authorization-code clients without PKCE.
Provisioning stamps schema/owner/manifest identity properties and records
explicit adoptions in the management audit stream. The remaining P0.1 work is
deliberately kept open: inventory/adoption of existing production manifests
before enforcement.

**Done when:** all three client-definition entry points share one validator, reconciliation cannot silently claim an unmanaged client, and current clients have an explicit ownership state without interruption.

This expands the canonical work already tracked in `PLAN-GLM-5-2-REMAINING.md` P0.2; close both checklist entries in the same implementation.

### P0.2 Centralize local redirect validation

**Targets:** `LowercasePathMiddleware`, `LocalUrlValidator`, middleware tests.

- [x] Make `LocalUrlValidator` the sole decision point for every caller-supplied local redirect
- [x] Validate the decoded and canonicalized target before emitting the lowercase-path redirect; reject ambiguous slash/separator forms with `400`
- [x] Preserve `308` behavior for valid local uppercase paths and preserve query strings byte-for-byte where safe
- [x] Add a table-driven suite covering literal and encoded separators, duplicate separators, authority-like paths, path-base hosting, and valid local paths

**Done when:** middleware cannot emit a redirect that the shared local-URL policy rejects, with no route removed or renamed.

### P0.3 Make certificate startup fail closed without an elevated mutable-script path

**Targets:** `helpers/prestart.sh`, `helpers/sufficit-identity.service`, installation packaging, deployment tests.

- [x] Remove the systemd prefix that ignores `ExecStartPre` failure; keep startup blocked outside Development when signing material is unavailable or invalid
- [x] Install prestart helpers as root-owned, non-writable by the service account; replace recursive ownership changes with an explicit allow-list of runtime-writable directories
- [x] Separate privileged installation/bootstrap from unprivileged runtime validation; the service account must never control code later executed with elevated privileges
- [x] Keep automatic self-signed certificate generation Development-only and remove the repository-literal PFX password from the generation path
- [x] Validate certificate purpose, private-key availability, expiry window, issuer policy, and file ownership before process start
- [ ] Audit and rotate any production signing material that may have been created through the legacy helper path; this is operational and must record only certificate thumbprints/versions, never keys or passwords
- [x] Add `systemd-analyze verify`, ownership assertions, and a negative integration test proving that missing production signing material prevents startup

**Done when:** a failed certificate precondition stops the service and no service-owned file is executed with elevated privilege. Existing valid production certificates continue loading unchanged.

### P0.4 Introduce one CIBA client and request-binding policy

**Targets:** `CibaController`, CIBA stores/contracts, client-definition validation, CIBA tests.

- [x] Add `ICibaClientPolicy` and invoke it identically from initiation and polling
- [x] Require the configured CIBA client authentication method and dedicated grant entitlement; do not infer authorization merely from client existence or requested scopes
- [x] Bind the pending request to the authenticated client identity and verify that binding atomically during every state transition
- [ ] Inventory current CIBA callers in Observe mode, provision missing entitlements, then enforce per client
- [ ] Add tests for public/unauthenticated callers, missing grant entitlement, mismatched polling client, replay, concurrent poll/approval, and rolling-deployment compatibility

**Done when:** CIBA remains available, but every successful initiation/poll is attributable to an explicitly entitled authenticated client.

### P0.5 Constrain personal token issuance without removing it

**Targets:** personal-token controller/handler, claim/scope policy, credential-mutation coordinator, DPoP policy.

- [x] Introduce `IPersonalTokenIssuancePolicy` with caller-client eligibility, subject eligibility, required management/self-service scope, authentication freshness/ACR, lifetime, and sender-constraint decisions
- [x] Calculate issued scopes as the intersection of explicitly requested scopes, caller-held scopes, and server-side client/subject allowances; never default to the union of every known application scope
- [x] Preserve the current endpoint through Observe mode, publish decision telemetry, and migrate callers before enforcement
- [x] Coordinate token revocation with password reset, MFA/passkey mutation, account disablement, and security-stamp changes
- [x] Bind tokens to DPoP when required by the caller or issuance policy and carry the binding through refresh/introspection validation
- [x] Add claims-diff characterization tests so the rollout cannot accidentally drop legitimate identity claims

**Done when:** personal tokens remain usable, but cannot exceed the caller's delegated authority or outlive relevant credential state.

### P0.6 Keep the SCIM client allow-list independent of scope compatibility

**Targets:** `ScimServiceCollectionExtensions`, `ScimOptions`, `ScimClientRequirement`, SCIM authorization tests.

- [x] Split the existing switch into `RequireScope` and `RequireAllowedClient`; retain `RequireAuthorization` as a deprecated compatibility alias for one release
- [ ] Always require an authenticated, allow-listed client outside Development; an empty production allow-list fails startup once inventory is complete
- [x] Keep scope relaxation available for legacy clients during migration, while client identity remains mandatory
- [ ] Add Observe mode and audit the client/scope decision independently
- [x] Add tests proving that `RequireAuthorization=false` does not grant an ordinary authenticated token SCIM access

**Done when:** existing provisioning continues, and relaxing a legacy scope requirement cannot remove the independent machine-client boundary.

### P0.7 Protect target principals and make object/context policy real

**Targets:** `UserManagementService`, all credential/profile/role/claim mutation services, `IManagementObjectAccessPolicy`, management UI authorization calls.

- [x] Introduce `IProtectedPrincipalAccessPolicy` based on capability subset and an explicit protected-principal tier, with an audited break-glass decision
- [ ] Apply it consistently to password reset, email/profile mutation, lockout/disable/delete, MFA/passkey changes, roles, claims, and session revocation
- [x] Define collection resources separately from item resources; require an actual resource ID for item decisions
- [x] Implement the context model, backfill current data into a legacy/global context, and add a concrete non-permissive `IManagementObjectAccessPolicy`
- [x] Treat management UI authorization as presentation guidance only; application services remain the authoritative enforcement boundary
- [ ] Compare permissive and concrete decisions in shadow telemetry before enforcing per resource type
- [ ] Add higher/equal-principal, cross-context read/write/enumeration, guessed-ID, collection, and break-glass audit tests

**Done when:** an operator cannot mutate a principal or object outside their authority, while current global administrators retain access through explicit legacy-context and break-glass assignments.

This is the same canonical object-policy migration tracked in `PLAN-GLM-5-2-REMAINING.md` P0.3.

## P1 — protocol integrity, data correctness, and supply chain

### P1.1 Make access-token claim release fail closed

**Targets:** `ApplicationClaimDestinationPolicy`, `ClaimScopeMapOptions`, claim inventory/tests.

- [ ] Inventory every custom claim emitted in production and assign a required scope, token destination, sensitivity, and owning component
- [x] Add telemetry for unmapped-claim suppression decisions without logging values
- [x] Deny high-sensitivity unmapped claims immediately while the compatibility bridge remains enabled
- [ ] Migrate the remaining claim mappings, then change `IncludeUnmappedClaimsInAccessTokens` to `false`
- [x] Add access-token/identity-token matrix tests for mapped, unmapped, requested, and unrequested scopes

### P1.2 Require subject-token provenance in token exchange

**Targets:** token-exchange branch in `AuthorizationController`, future extracted grant handler.

- [x] Introduce `ISubjectTokenProvenancePolicy` that resolves issuer, subject, authorized party, sender constraint, and token type
- [x] When a source-client allow-list is enabled, reject absent or ambiguous authorized-party identity rather than treating it as compatible
- [ ] Characterize legacy tokens in Observe mode and migrate issuers/claims before enforcement
- [ ] Add missing-`azp`, foreign issuer, mismatched client, personal-token, CIBA-token, and sender-binding tests

### P1.3 Fail closed on unknown consent configuration

**Targets:** authorization consent decision, application data migration, provisioning/client validators.

- [x] Replace the default fallthrough with an explicit typed consent policy
- [ ] Backfill null/unknown values to the intended legacy mode before enforcing validation
- [x] Reject new client definitions with unknown consent types
- [x] Add null, unknown, explicit, external, implicit, and systematic consent tests

### P1.4 Partition DPoP nonce state

**Targets:** `DistributedDpopNonceStore`, DPoP handlers and tests.

- [x] Replace the global nonce key with a partition derived from endpoint, client identity, and proof-key thumbprint, or adopt a bounded stateless signed nonce design
- [x] Permit a short current/previous overlap to tolerate concurrent requests without weakening expiry
- [ ] Make issue/consume atomic in the shared store and add multi-replica concurrency tests

### P1.5 Bind FAPI mTLS evidence to the client

**Targets:** `Fapi2Policy`, new `IMtlsClientCertificatePolicy`, proxy/certificate configuration.

- [x] Validate certificate chain/trust source and bind client ID to configured thumbprint, SAN, or registered certificate metadata
- [ ] Accept forwarded certificate evidence only from explicitly trusted proxies and after signature/format validation
- [x] Fail startup when a client selects mTLS sender constraint without a configured binding policy
- [ ] Add wrong-client, untrusted-chain, trusted-proxy, direct-connection, rollover-overlap, and expiry tests

### P1.6 Restore per-client OAuth resource validation

**Targets:** STS OpenIddict registration, MCP resource registration/permission validation, authorization tests.

- [x] Remove the global `DisableResourceValidation` dependency
- [x] Register static resource/audience definitions where possible; for dynamic MCP resources, introduce an `IRequestedResourcePolicy` that validates canonical URI, client permission, scope, and deployment allow-list
- [ ] Run the new policy in Observe mode and provision explicit resource permissions for existing MCP clients
- [x] Add tests proving unrelated clients cannot request arbitrary resources while current MCP resources continue to work

### P1.7 Bind browser session identifiers to their subject

**Targets:** `OidcSessionClaimsPrincipalFactory`, session store, external-login/account-switch tests.

- [x] Reuse a `sid` only when the current principal subject equals the target user and the persisted session row belongs to that subject
- [x] Create a fresh session for account switching, linking, impersonation, or missing persistence evidence
- [x] Add subject-switch, external-login, impersonation, stale-cookie, and rolling-deployment tests

### P1.8 Establish provider and container provenance

**Targets:** `nuget.config`, `Directory.Packages.props`, local provider fork/package, Dockerfile, CI.

- [ ] Prefer an approved upstream EF Core 10 provider after MariaDB contract/canary validation; follow `PLAN-GLM-5-2-REMAINING.md` P1.8 for retirement
- [ ] If the fork remains temporarily, publish it under a Sufficit-owned package ID with repository URL, commit, license, deterministic-build, and SBOM metadata
- [x] Add NuGet package source mapping so only the fork package can resolve from the private/local source
- [ ] Build the package in CI from a pinned fork commit and compare the produced artifact/hash; checksum of an opaque committed package is not sufficient provenance
- [ ] Run vulnerability/license scanning against source and final dependency graph
- [x] Change Docker restore to locked mode and add the container build to CI; retain the existing pinned base-image digests

### P1.9 Rate-limit anonymous device information independently

**Targets:** device information endpoint, rate-limiter partition configuration, tests.

- [x] Add a named GET limiter partitioned by trusted client identity when present and otherwise by validated remote IP
- [x] Keep the existing credential POST limiter independent; do not blanket-limit unrelated GET endpoints
- [x] Return uniform invalid-code responses and add enumeration, burst, proxy, and legitimate polling tests

### P1.10 Centralize dynamic client registration policy

**Targets:** `RegistrationController`, `IClientDefinitionValidator`, secret generator/resolver, DCR tests.

- [x] Route DCR through the shared typed client validator from P0.1
- [x] Generate high-entropy secrets server-side, store only the OpenIddict-protected representation, and return plaintext once
- [ ] Retain caller-supplied secrets only behind a deprecated audited adapter during migration, with an entropy floor and deadline
- [x] Require PKCE S256 for every authorization-code client unless a separately reviewed profile explicitly proves an exception
- [x] Add grant/redirect/scope/secret/PKCE negative tests and secret non-disclosure tests

### P1.11 Restore fresh-install and additive SQL parity

**Targets:** `docs/migration/sql`, EF migrations, `DatabaseSchemaContractTests`, `MariaDbMigrationIntegrationTests`.

- [x] Add idempotent numbered additive scripts for identity application metrics, hardened SSF columns/indexes, and atomic CIBA/DPoP protocol state
- [x] Include the corresponding migration-history markers only after each schema assertion succeeds
- [x] Extend the CI rehearsal to execute the current additive hardening scripts twice against the MariaDB service
- [ ] Compare the resulting legacy-schema state with the canonical fresh-install schema for every additive script through HEAD
- [x] Fail CI whenever an EF migration has neither canonical nor additive deployment coverage

### P1.12 Enforce unambiguous normalized email identity

**Targets:** `AppDbContext`, onboarding/recovery, SCIM provisioning, additive migration/tests.

- [x] Produce a redacted duplicate-normalized-email report and guard schema enforcement until an operator workflow resolves every collision
- [x] Introduce `IAccountLookupPolicy` that handles absent/ambiguous matches uniformly and never chooses an arbitrary recovery target
- [x] Add a provider-compatible nullable unique index strategy for normalized email after collision count reaches zero
- [ ] Preserve existing accounts during cleanup; add registration, SCIM update, email change, login, and recovery race tests

### P1.13 Encrypt authenticator and recovery material with a compatible store adapter

**Targets:** ASP.NET Core Identity token store registration, `AspNetCoreIdentityAccountTwoFactorService`, vault, additive migration/tests.

- [ ] Introduce an `IUserAuthenticationSecretStore` boundary backed by envelope encryption with user ID, login provider, and token name as AAD
- [ ] Implement dual-read: decrypt versioned ciphertext, accept legacy plaintext, and rewrite legacy values on successful read/mutation
- [ ] Add a background migration with checkpoints and redacted progress metrics; do not reset or disable existing MFA
- [ ] Coordinate secret rotation with security-stamp/session/token revocation and recovery-code regeneration
- [ ] Enable fail-closed encrypted writes first, then disable plaintext reads only after migration telemetry reaches zero

## P2 — production posture and maintainability

### P2.1 Model deployment topology explicitly

**Targets:** host options/validation, forwarded headers, distributed cache, startup health.

- [x] Add `DeploymentTopology = SingleReplica | Clustered | BehindTrustedProxy | ClusteredBehindTrustedProxy`
- [x] Validate coherent proxy, shared-cache, Data Protection, certificate, and remote-IP settings for the selected topology
- [ ] Inventory the current production topology, configure it explicitly, and then make `FailOnUntrustedProxy`/`RequireShared` derived fail-closed requirements
- [x] Add startup-contract tests for every topology
- [ ] Add a two-replica DPoP/CIBA/passkey smoke test

### P2.2 Move CSP from telemetry to enforcement

**Targets:** CSP options/middleware, embedded UI assets, production-readiness plan.

- [x] Remove placeholder external hosts
- [ ] Inventory actual image/style/script origins against the rendered UI
- [ ] Replace inline-style allowances with nonces, hashes, or extracted static styles
- [ ] Exercise all public and management flows in report-only mode, triage violations, then enforce by deployment cohort
- [ ] Keep a bounded report-only rollback switch and record no sensitive URL/query data in reports

Track closure in `PLAN-PRODUCTION-READINESS.md` to avoid parallel CSP checklists.

### P2.3 Require verified database transport in production

**Targets:** connection configuration/options validation, deployment templates, database runbook.

- [x] Introduce an environment-aware database transport policy requiring certificate verification when `RequireVerifiedTls` is selected
- [x] Support an explicit, audited local-socket/private-lab exception rather than a silent insecure default
- [x] Validate CA/certificate availability at startup and add positive/negative policy tests
- [ ] Select `RequireVerifiedTls` (or the audited `PrivateSocket` exception) in each production deployment after CA/socket provisioning

This is primarily operational configuration; the software-design lever is central startup validation rather than scattering connection-string checks.

### P2.4 Move MariaDB to a supported baseline without a flag day

**Targets:** CI service matrix, provider compatibility, migration rehearsal, production rollout.

- [ ] Select a currently supported MariaDB LTS target compatible with the provider
- [ ] Run old and target versions in CI, including canonical schema, additive rehearsal, grants, concurrency, locking, collations, and index-width behavior
- [ ] Canary production-shaped traffic, migrate replicas/backups, and retain 10.4 compatibility until the production cutover is complete
- [ ] Remove the 10.4 lane only after rollback and restore rehearsals succeed on the target version

This is primarily an operational platform upgrade; no STS feature should change during it.

### P2.5 Separate vault wrapping keys and operationalize rotation

**Targets:** `IKeyVault`, `DataProtectionKeySource`, new key-source abstraction, management job/runbook, `PLAN-VAULT.md`.

- [x] Extract `IVaultKeyEncryptionKeySource`; keep Data Protection as the compatibility implementation
- [ ] Add a certificate/external KMS implementation behind the wrapping-key source boundary
- [ ] Add an authorized rotation orchestrator with distributed lock, progress journal, rewrap/re-encrypt strategy, rollback window, and audit events
- [ ] Separate database-reader authority from KEK authority in production
- [ ] Exercise loss/recovery, old-version decrypt, concurrent rotate/encrypt, and disaster-restore tests

Track the full lifecycle in `PLAN-VAULT.md`; this checklist defines only the missing boundary discovered in the reconciliation.

### P2.6 Correct security-critical protocol annotations

**Targets:** CIBA source comments/XML docs, discovery comments, tests that encode standards references.

- [x] Attribute PAR to RFC 9126 and CIBA to OpenID Connect Client-Initiated Backchannel Authentication Core 1.0
- [ ] Remove comments that claim a guard is unconditional when composition makes it conditional
- [ ] Review security comments against executable tests and delete historical “item fixed” narratives that no longer describe current behavior

Comments are not security controls, but inaccurate protocol annotations increase maintenance and review risk.

## Regression-only items already closed

These are excluded from implementation scope unless a regression appears:

- [x] Outbound HTTP clients use the safe handler path, including DNS-to-connect binding
- [x] SSF streams and operations are scoped to their owner client, with migration compatibility for legacy rows
- [x] MariaDB integration tests fail in CI when required infrastructure variables are absent and include a real-provider grant smoke test

## Delivery order and release gates

| Wave | Scope | Enforcement gate |
|---|---|---|
| 0 | telemetry, client/principal/resource inventory, explicit deployment topology | dashboards and redacted audit events deployed; no decisions changed |
| 1 | P0.2 and P0.3 plus P0 policy abstractions in Observe mode | redirect/certificate regression tests green; no unexplained shadow denials |
| 2 | P0.1, P0.4, P0.5, P0.6, P0.7 by client/resource cohort | affected clients provisioned with explicit ownership/permissions; rollback switch tested |
| 3 | P1 protocol policies and additive data migrations | claims/token/schema diffs reviewed; dual-read/backfill telemetry at target |
| 4 | P2 topology, CSP, database, vault, and platform cutovers | canary, restore, multi-replica, and rollback rehearsals green |

Every pull request must name the checklist item, add negative tests before enforcement, document compatibility behavior, and avoid mixing unrelated policy activations in one deployment.

## Closure criteria

- [ ] Every Open/Partial row is either implemented and regression-tested or linked to an explicitly accepted risk with owner and expiry
- [ ] Observe-mode telemetry has no unexplained future denials for the cohort being enabled
- [ ] No production feature, grant, endpoint, client type, or user journey was removed to close an item
- [ ] Fresh-install and additive-upgrade schemas are equivalent at HEAD
- [ ] CI covers supported database versions, locked restore/container build, security boundary tests, and secret scanning
- [ ] A coordinated disclosure decision has been made before adding the confidential review identifier or reproduction details to this public repository
