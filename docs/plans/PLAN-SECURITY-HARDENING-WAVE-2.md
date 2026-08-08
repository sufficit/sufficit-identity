# Security hardening — compatibility rollout wave 2

> **Status:** ACTIVE. Reconciled against `79e0f82ac5a9346378de7f92dd37acceace0a875` on 2026-08-07.
>
> **Disclosure note:** this repository is public. This plan records implementation work and acceptance criteria, but intentionally omits the confidential review identifier, reproduction steps, payloads, and exploitation scenarios. Those details remain in the restricted security-review channel until coordinated disclosure.

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
| Signing-certificate prestart boundary | **Partial** | `prestart.sh` fails outside Development when configuration is absent, but the systemd unit ignores the prestart exit code and executes a release-owned helper with elevated privilege | P0.3 |
| CIBA client policy | **Open** | initiation and polling do not share a policy that always requires the intended client authentication and grant entitlement | P0.4 |
| Personal token issuance policy | **Open** | the endpoint authenticates the caller but does not centrally constrain requested scopes, authentication freshness, client eligibility, and sender binding | P0.5 |
| Management grant/permission parsing | **Open** | `ClientManagementService.NormalizeGrantTypes` accepts unrecognized values instead of producing typed, allow-listed permissions | P0.1 |
| SCIM client boundary when scope enforcement is relaxed | **Open** | `ScimServiceCollectionExtensions` applies the client allow-list only inside the `RequireAuthorization` branch | P0.6 |
| Protected-principal mutations | **Open** | user credential/profile mutations have capability checks but no concrete target-principal hierarchy policy | P0.7 |
| Object/context authorization | **Partial** | the `IManagementObjectAccessPolicy` seam is called, but the default production implementation allows every object and some UI checks omit resource identifiers | P0.7 / existing GLM plan P0.3 |
| Database-provider provenance | **Open** | the local provider fork uses an upstream package identity, a local feed without source mapping, and checksum-only CI verification | P1.8 |
| Custom claim release | **Open** | unmapped custom claims remain eligible for access tokens by default | P1.1 |
| Token-exchange source-client attribution | **Open** | an enabled allow-list does not reject a subject token whose authorized-party identity is absent | P1.2 |
| Unknown/null consent mode | **Resolved at runtime; data cleanup pending** | `AuthorizationConsentPolicy` maps missing/unrecognized legacy metadata to interactive consent, while current management, provisioning, and DCR paths accept only known/default consent modes | P1.3 |
| DPoP nonce partitioning | **Open** | `DistributedDpopNonceStore` uses one global current-nonce key | P1.4 |
| FAPI mTLS client binding | **Open** | presence of a client certificate counts as strong authentication without application-specific certificate binding | P1.5 |
| OAuth resource validation | **Open** | MCP resource configuration globally disables OpenIddict resource validation | P1.6 |
| Browser-session `sid` reuse | **Open** | `OidcSessionClaimsPrincipalFactory` can reuse the request principal's `sid` without first proving it belongs to the target subject | P1.7 |
| Anonymous device-information throttling | **Partial** | response detail was reduced, but the GET endpoint is outside the credential-endpoint limiter | P1.9 |
| Proxy/shared-cache topology guards | **Partial** | guards exist but defaults remain compatibility-oriented and topology is not modeled explicitly | P2.1 |
| CSP enforcement | **Partial** | report-only remains the default and the policy still contains inline-style and placeholder host allowances | P2.2 / production-readiness plan |
| Dynamic client registration policy | **Open** | caller-supplied secrets are accepted and PKCE is not uniformly required for authorization-code clients | P1.10 |
| Canonical/additive SQL parity | **Partial** | fresh-install SQL contains current tables, but additive SQL stops before application metrics, SSF hardening, and atomic protocol-state migrations | P1.11 |
| Reproducible container restore | **Open** | Docker restore does not use locked mode | P1.8 |
| Production database transport | **Open** | production templates do not establish a verified TLS contract for the database connection | P2.3 |
| Email identity uniqueness | **Open** | `EmailIndex` is non-unique while account recovery uses `FindByEmailAsync` | P1.12 |
| MariaDB support baseline | **Open** | CI and provider configuration remain fixed to MariaDB 10.4.34 | P2.4 |
| Vault separation and rotation operations | **Partial** | envelope encryption and versioned DEKs exist, but only the Data Protection key source is implemented and no production rotation orchestrator calls `RotateKeyAsync` | P2.5 / vault plan |
| Authenticator/recovery secret-at-rest boundary | **Open** | the standard Identity token store persists authenticator/recovery material through `usertokens` without an application encryption adapter | P1.13 |
| Security-critical protocol comments | **Open** | CIBA comments attribute the protocol to RFC 9126, which actually specifies PAR | P2.6 |
| MariaDB integration-test gating | **Resolved** | missing MariaDB/rehearsal configuration fails tests in CI; real-provider grant and schema tests execute against the service container | Regression-only |

## P0 — close direct authorization and deployment boundaries

### P0.1 Unify client-definition validation and protect provisioned ownership

**Targets:** `OpenIddictManifestProvisioner`, `IdentityProvisioningManifestValidator`, `ClientManagementService`, `RegistrationController`, Application Abstractions.

- [ ] Extract an `IClientDefinitionValidator` that receives the actor, source (`management`, `provisioning`, or `dcr`), current descriptor, desired descriptor, and rollout mode
- [ ] Replace raw string grant/endpoint/scope permissions with typed value objects and an exhaustive mapping; reject unknown values before an OpenIddict descriptor is built
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
Provisioning stamps schema/owner/manifest identity properties, records explicit
adoptions in the management audit stream, authorizes sensitive transitions with
an actor plus explicit approval, and records Observe-mode future denials without
mutating clients. The remaining P0.1 work is deliberately kept open:
inventory/adoption of existing production manifests before enforcement.

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

- [ ] Remove the systemd prefix that ignores `ExecStartPre` failure; keep startup blocked outside Development when signing material is unavailable or invalid
- [ ] Install prestart helpers as root-owned, non-writable by the service account; replace recursive ownership changes with an explicit allow-list of runtime-writable directories
- [ ] Separate privileged installation/bootstrap from unprivileged runtime validation; the service account must never control code later executed with elevated privileges
- [ ] Keep automatic self-signed certificate generation Development-only and remove the repository-literal PFX password from the generation path
- [ ] Validate certificate purpose, private-key availability, expiry window, issuer policy, and file ownership before process start
- [ ] Audit and rotate any production signing material that may have been created through the legacy helper path; this is operational and must record only certificate thumbprints/versions, never keys or passwords
- [ ] Add `systemd-analyze verify`, ownership assertions, and a negative integration test proving that missing production signing material prevents startup

**Done when:** a failed certificate precondition stops the service and no service-owned file is executed with elevated privilege. Existing valid production certificates continue loading unchanged.

### P0.4 Introduce one CIBA client and request-binding policy

**Targets:** `CibaController`, CIBA stores/contracts, client-definition validation, CIBA tests.

- [ ] Add `ICibaClientPolicy` and invoke it identically from initiation and polling
- [ ] Require the configured CIBA client authentication method and dedicated grant entitlement; do not infer authorization merely from client existence or requested scopes
- [ ] Bind the pending request to the authenticated client identity and verify that binding atomically during every state transition
- [ ] Inventory current CIBA callers in Observe mode, provision missing entitlements, then enforce per client
- [ ] Add tests for public/unauthenticated callers, missing grant entitlement, mismatched polling client, replay, concurrent poll/approval, and rolling-deployment compatibility

**Done when:** CIBA remains available, but every successful initiation/poll is attributable to an explicitly entitled authenticated client.

### P0.5 Constrain personal token issuance without removing it

**Targets:** personal-token controller/handler, claim/scope policy, credential-mutation coordinator, DPoP policy.

- [ ] Introduce `IPersonalTokenIssuancePolicy` with caller-client eligibility, subject eligibility, required management/self-service scope, authentication freshness/ACR, lifetime, and sender-constraint decisions
- [ ] Calculate issued scopes as the intersection of explicitly requested scopes, caller-held scopes, and server-side client/subject allowances; never default to the union of every known application scope
- [ ] Preserve the current endpoint through Observe mode, publish decision telemetry, and migrate callers before enforcement
- [ ] Coordinate token revocation with password reset, MFA/passkey mutation, account disablement, and security-stamp changes
- [ ] Bind tokens to DPoP when required by the caller or issuance policy and carry the binding through refresh/introspection validation
- [ ] Add claims-diff characterization tests so the rollout cannot accidentally drop legitimate identity claims

**Done when:** personal tokens remain usable, but cannot exceed the caller's delegated authority or outlive relevant credential state.

### P0.6 Keep the SCIM client allow-list independent of scope compatibility

**Targets:** `ScimServiceCollectionExtensions`, `ScimOptions`, `ScimClientRequirement`, SCIM authorization tests.

- [ ] Split the existing switch into `RequireScope` and `RequireAllowedClient`; retain `RequireAuthorization` as a deprecated compatibility alias for one release
- [ ] Always require an authenticated, allow-listed client outside Development; an empty production allow-list fails startup once inventory is complete
- [ ] Keep scope relaxation available for legacy clients during migration, while client identity remains mandatory
- [ ] Add Observe mode and audit the client/scope decision independently
- [ ] Add tests proving that `RequireAuthorization=false` does not grant an ordinary authenticated token SCIM access

**Done when:** existing provisioning continues, and relaxing a legacy scope requirement cannot remove the independent machine-client boundary.

### P0.7 Protect target principals and make object/context policy real

**Targets:** `UserManagementService`, all credential/profile/role/claim mutation services, `IManagementObjectAccessPolicy`, management UI authorization calls.

- [ ] Introduce `IProtectedPrincipalAccessPolicy` based on capability subset and an explicit protected-principal tier, with an audited break-glass decision
- [ ] Apply it consistently to password reset, email/profile mutation, lockout/disable/delete, MFA/passkey changes, roles, claims, and session revocation
- [ ] Define collection resources separately from item resources; require an actual resource ID for item decisions
- [ ] Implement the context model, backfill current data into a legacy/global context, and add a concrete non-permissive `IManagementObjectAccessPolicy`
- [ ] Treat management UI authorization as presentation guidance only; application services remain the authoritative enforcement boundary
- [ ] Compare permissive and concrete decisions in shadow telemetry before enforcing per resource type
- [ ] Add higher/equal-principal, cross-context read/write/enumeration, guessed-ID, collection, and break-glass audit tests

**Done when:** an operator cannot mutate a principal or object outside their authority, while current global administrators retain access through explicit legacy-context and break-glass assignments.

This is the same canonical object-policy migration tracked in `PLAN-GLM-5-2-REMAINING.md` P0.3.

## P1 — protocol integrity, data correctness, and supply chain

### P1.1 Make access-token claim release fail closed

**Targets:** `ApplicationClaimDestinationPolicy`, `ClaimScopeMapOptions`, claim inventory/tests.

- [ ] Inventory every custom claim emitted in production and assign a required scope, token destination, sensitivity, and owning component
- [ ] Add telemetry for unmapped-claim suppression decisions without logging values
- [ ] Deny high-sensitivity unmapped claims immediately; migrate remaining mappings, then change `IncludeUnmappedClaimsInAccessTokens` to `false`
- [ ] Add access-token/identity-token matrix tests for mapped, unmapped, requested, and unrequested scopes

### P1.2 Require subject-token provenance in token exchange

**Targets:** token-exchange branch in `AuthorizationController`, future extracted grant handler.

- [ ] Introduce `ISubjectTokenProvenancePolicy` that resolves issuer, subject, authorized party, sender constraint, and token type
- [ ] When a source-client allow-list is enabled, reject absent or ambiguous authorized-party identity rather than treating it as compatible
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

- [ ] Replace the global nonce key with a partition derived from endpoint, client identity, and proof-key thumbprint, or adopt a bounded stateless signed nonce design
- [ ] Permit a short current/previous overlap to tolerate concurrent requests without weakening expiry
- [ ] Make issue/consume atomic in the shared store and add multi-replica concurrency tests

### P1.5 Bind FAPI mTLS evidence to the client

**Targets:** `Fapi2Policy`, new `IMtlsClientCertificatePolicy`, proxy/certificate configuration.

- [ ] Validate certificate chain/trust source and bind client ID to configured thumbprint, SAN, or registered certificate metadata
- [ ] Accept forwarded certificate evidence only from explicitly trusted proxies and after signature/format validation
- [ ] Fail startup when a client selects mTLS sender constraint without a configured binding policy
- [ ] Add wrong-client, untrusted-chain, trusted-proxy, direct-connection, rollover-overlap, and expiry tests

### P1.6 Restore per-client OAuth resource validation

**Targets:** STS OpenIddict registration, MCP resource registration/permission validation, authorization tests.

- [ ] Remove the global `DisableResourceValidation` dependency
- [ ] Register static resource/audience definitions where possible; for dynamic MCP resources, introduce an `IRequestedResourcePolicy` that validates canonical URI, client permission, scope, and deployment allow-list
- [ ] Run the new policy in Observe mode and provision explicit resource permissions for existing MCP clients
- [ ] Add tests proving unrelated clients cannot request arbitrary resources while current MCP resources continue to work

### P1.7 Bind browser session identifiers to their subject

**Targets:** `OidcSessionClaimsPrincipalFactory`, session store, external-login/account-switch tests.

- [ ] Reuse a `sid` only when the current principal subject equals the target user and the persisted session row belongs to that subject
- [ ] Create a fresh session for account switching, linking, impersonation, or missing persistence evidence
- [ ] Add subject-switch, external-login, impersonation, stale-cookie, and rolling-deployment tests

### P1.8 Establish provider and container provenance

**Targets:** `nuget.config`, `Directory.Packages.props`, local provider fork/package, Dockerfile, CI.

- [ ] Prefer an approved upstream EF Core 10 provider after MariaDB contract/canary validation; follow `PLAN-GLM-5-2-REMAINING.md` P1.8 for retirement
- [ ] If the fork remains temporarily, publish it under a Sufficit-owned package ID with repository URL, commit, license, deterministic-build, and SBOM metadata
- [ ] Add NuGet package source mapping so only the fork package can resolve from the private/local source
- [ ] Build the package in CI from a pinned fork commit and compare the produced artifact/hash; checksum of an opaque committed package is not sufficient provenance
- [ ] Run vulnerability/license scanning against source and final dependency graph
- [ ] Change Docker restore to locked mode and add the container build to CI; retain the existing pinned base-image digests

### P1.9 Rate-limit anonymous device information independently

**Targets:** device information endpoint, rate-limiter partition configuration, tests.

- [ ] Add a named GET limiter partitioned by trusted client identity when present and otherwise by validated remote IP
- [ ] Keep the existing credential POST limiter independent; do not blanket-limit unrelated GET endpoints
- [ ] Return uniform invalid-code responses and add enumeration, burst, proxy, and legitimate polling tests

### P1.10 Centralize dynamic client registration policy

**Targets:** `RegistrationController`, `IClientDefinitionValidator`, secret generator/resolver, DCR tests.

- [x] Route DCR through the shared typed client validator from P0.1
- [ ] Generate high-entropy secrets server-side, store only the OpenIddict-protected representation, and return plaintext once
- [ ] Retain caller-supplied secrets only behind a deprecated audited adapter during migration, with an entropy floor and deadline
- [ ] Require PKCE S256 for every authorization-code client unless a separately reviewed profile explicitly proves an exception
- [ ] Add grant/redirect/scope/secret/PKCE negative tests and secret non-disclosure tests

### P1.11 Restore fresh-install and additive SQL parity

**Targets:** `docs/migration/sql`, EF migrations, `DatabaseSchemaContractTests`, `MariaDbMigrationIntegrationTests`.

- [ ] Add idempotent numbered additive scripts for identity application metrics, hardened SSF columns/indexes, and atomic CIBA/DPoP protocol state
- [ ] Include the corresponding migration-history markers only after each schema assertion succeeds
- [ ] Extend the legacy-schema rehearsal to apply every additive script through HEAD twice and compare the resulting schema with the canonical fresh-install schema
- [ ] Fail CI whenever an EF migration has neither canonical nor additive deployment coverage

### P1.12 Enforce unambiguous normalized email identity

**Targets:** `AppDbContext`, onboarding/recovery, SCIM provisioning, additive migration/tests.

- [ ] Produce a redacted duplicate-normalized-email report and resolve collisions through an operator workflow before schema enforcement
- [ ] Introduce `IAccountLookupPolicy` that handles absent/ambiguous matches uniformly and never chooses an arbitrary recovery target
- [ ] Add a provider-compatible unique index strategy for non-null normalized email after collision count reaches zero
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

- [ ] Add `DeploymentTopology = SingleReplica | Clustered | BehindTrustedProxy | ClusteredBehindTrustedProxy`
- [ ] Validate coherent proxy, shared-cache, Data Protection, certificate, and remote-IP settings for the selected topology
- [ ] Inventory the current production topology, configure it explicitly, and then make `FailOnUntrustedProxy`/`RequireShared` derived fail-closed requirements
- [ ] Add startup-contract tests for every topology and a two-replica DPoP/CIBA/passkey smoke test

### P2.2 Move CSP from telemetry to enforcement

**Targets:** CSP options/middleware, embedded UI assets, production-readiness plan.

- [ ] Remove placeholder external hosts and inventory actual image/style/script origins
- [ ] Replace inline-style allowances with nonces, hashes, or extracted static styles
- [ ] Exercise all public and management flows in report-only mode, triage violations, then enforce by deployment cohort
- [ ] Keep a bounded report-only rollback switch and record no sensitive URL/query data in reports

Track closure in `PLAN-PRODUCTION-READINESS.md` to avoid parallel CSP checklists.

### P2.3 Require verified database transport in production

**Targets:** connection configuration/options validation, deployment templates, database runbook.

- [ ] Introduce an environment-aware database transport policy requiring certificate verification in production
- [ ] Support an explicit, audited local-socket/private-lab exception rather than a silent insecure default
- [ ] Validate CA/certificate availability at startup and add positive/negative connection tests

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

- [ ] Extract `IVaultKeyEncryptionKeySource`; keep Data Protection as the compatibility implementation and add a certificate/external KMS implementation
- [ ] Add an authorized rotation orchestrator with distributed lock, progress journal, rewrap/re-encrypt strategy, rollback window, and audit events
- [ ] Separate database-reader authority from KEK authority in production
- [ ] Exercise loss/recovery, old-version decrypt, concurrent rotate/encrypt, and disaster-restore tests

Track the full lifecycle in `PLAN-VAULT.md`; this checklist defines only the missing boundary discovered in the reconciliation.

### P2.6 Correct security-critical protocol annotations

**Targets:** CIBA source comments/XML docs, discovery comments, tests that encode standards references.

- [ ] Attribute PAR to RFC 9126 and CIBA to OpenID Connect Client-Initiated Backchannel Authentication Core 1.0
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
