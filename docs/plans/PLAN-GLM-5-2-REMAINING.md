# GLM-5.2 evaluation — remaining work

> **Status:** ACTIVE. This plan contains only work that remained partial or unimplemented when `docs/archive/evaluations/EVALUATION-2026-08-06-GLM-5.2.md` was reconciled against `f97ef7e`. Completed work is recorded in `docs/activities/202608071210-completed-glm-5-2-remediation.md`.

## Delivery constraint

The STS is already serving production traffic. Every change below must preserve existing grants, endpoints, users, clients, and integrations during rollout. Use additive schema changes, compatibility adapters, audit/shadow decisions, dual-read or dual-write where state moves, and rolling deployment. A security policy becomes enforcing only after telemetry proves that current traffic satisfies it; no existing feature is removed as a migration shortcut.

## P0 — close the remaining authorization and secret boundaries

### 1. Complete the production secret lifecycle (C1 / Vault Phase 2)

**Current evidence:** a redacted full-directory Gitleaks scan found 13 credential/certificate findings in mode-`0600`, gitignored files under `deploy/local/` (PFX files, database/provider configuration, and human-verification credentials). Git exclusion prevents repository disclosure but does not remove the workstation/backup exposure identified by C1.

- [ ] Record evidence that the MySQL, Google, and Facebook credentials named by the old evaluation were rotated; retain owner, rotation date, and provider-side credential version, never the secret value
- [ ] Inventory and migrate every credential/certificate currently detected under `deploy/local/`; keep a redacted manifest of owner, purpose, source, target secret store, rotation state, and retirement date
- [ ] Introduce a configuration-time secret boundary for database and external-provider credentials, building on `Sufficit.Identity.Vault` and the Phase 2 design in `PLAN-VAULT.md`; consumers must receive resolved values without reading plaintext machine-specific JSON
- [ ] Roll out encrypted values compatibly: deploy readers first, migrate/rewrite legacy `pt1` values, enable `Sufficit:Vault:Enabled`, then set `RequireEncryptionInProduction=true`
- [ ] Add a production-startup validation that rejects plaintext provider/client-secret material once migration telemetry reaches zero legacy reads
- [ ] Add a redacted deployment check that scans machine-specific configuration without printing matched values

**Done when:** rotation evidence exists outside source control, no production secret depends on plaintext JSON, vault encryption is required in production, and rollback retains the preceding credential version only for a bounded overlap window.

### 2. Unify client-definition authorization (remaining H2)

- [ ] Extract `IClientDefinitionValidator` into Application Abstractions and use it from both `ClientManagementService` and `IdentityProvisioningManifestValidator`
- [ ] Introduce `IManagementScopeGrantPolicy` (the proposed `CanMintScope` responsibility) that evaluates operator, target client, grant type, and requested scopes
- [ ] Keep `ReservedApiScopes` as the non-bypassable floor, then add deployment-defined privileged scopes and operator-specific minting entitlements
- [ ] Replace the management HTTP contract's raw `ClientSecret` with a `SecretReference` path backed by `IClientSecretResolver`; retain the old field as a deprecated compatibility adapter during rollout and emit an audit warning whenever it is used
- [ ] Run the new validator in shadow mode against existing create/provision requests, compare decisions, then enforce after clients and operator roles are aligned

**Done when:** runtime CRUD and declarative provisioning share one validator; an operator cannot grant a scope they do not control; no new management request needs plaintext secret material; existing integrations continue through the compatibility adapter until migrated.

### 3. Supply a concrete object/tenant policy (remaining H3)

- [ ] Define the ownership model for users, clients, scopes, sessions, authorizations, branding, and provisioning manifests; introduce stable `ContextId` persistence where it does not yet exist
- [ ] Add `IManagementContextResolver` to resolve the operator's allowed contexts and a non-permissive `IManagementObjectAccessPolicy` implementation per `ManagementResourceType`
- [ ] Backfill current records into an explicit legacy/global context so existing single-operator behavior remains unchanged during migration
- [ ] Add shadow-decision telemetry comparing `DefaultManagementObjectAccessPolicy` with the concrete policy before enforcement
- [ ] Cover cross-context read, mutation, enumeration, and guessed-id tests; include collection resources, not only item-by-id paths
- [ ] Switch enforcement per resource type after zero unexpected shadow denials, retaining an audited break-glass global-administrator path

**Done when:** `ManagementResource.ContextId` affects authorization in the production composition, collection queries are context-filtered, and cross-context access is denied and tested without removing management functionality.

### 4. Replace SCIM full-directory trust with operation and partition policy (remaining M2/M4)

- [ ] Introduce `IScimOperationAuthorizationPolicy` with separate decisions for read, create/update, password mutation, membership mutation, and delete
- [ ] Preserve machine-to-machine provisioning: human/delegated tokens require MFA for destructive credential/account operations; client-credentials tokens require an explicitly granted destructive-operation permission plus the existing client allow-list and sender constraint (mTLS or DPoP)
- [ ] Add a client-to-partition binding and propagate it through `ScimRequestContext`; backfill existing data into a legacy/global partition
- [ ] Apply partition predicates to every Users/Groups query and mutation, including membership traversal and filter results
- [ ] Run dual-read comparison and authorization shadow logging before enforcing partition filters for each trusted provisioning client
- [ ] Add tests for cross-partition enumeration, password reset, delete, group nesting, and client allow-list bypass attempts

**Done when:** no ordinary SCIM client has implicit global-directory authority, destructive operations require stronger evidence appropriate to human or machine callers, and existing provisioning clients migrate without endpoint shutdown.

## P1 — compatibility and maintainability gaps

### 5. Make breached-password availability policy explicit (L2)

- [ ] Add `BreachedPasswordFailureMode = Allow | Deny | LocalFallback` to password options; default to `Allow` for compatibility
- [ ] Add a bounded local compromised-password fallback and cache successful HIBP range responses
- [ ] Add timeout, upstream-error, malformed-response, and recovery tests plus metrics that expose when validation ran degraded
- [ ] Move regulated environments to `LocalFallback` or `Deny` only after observing latency and availability in audit mode

### 6. Expand and extract SCIM query processing (L5 + decomposition)

- [ ] Extract `IScimFilterParser` and a typed filter AST from `ScimProvisioningService`; translate only validated nodes to parameterized LINQ
- [ ] Add `co`, `sw`, `ew`, logical composition, and multi-valued email/member filters required by current consumers
- [ ] Extract user and group provisioning services plus a shared PATCH applicator and repositories
- [ ] Add resource-limit, parser-timeout, invalid-filter, MariaDB translation, and interoperability tests
- [ ] Coordinate bulk, sorting, and ETag work with `PLAN-PRODUCTION-READINESS.md` rather than implementing parallel contracts

### 7. Decompose the authorization/token controller without changing routes

- [ ] Extract grant handlers from `AuthorizationController` behind a common issuance request/result contract while leaving the existing controller routes as adapters
- [ ] Centralize claim release, scope/resource/audience resolution, token lifetime, sender constraints, audit, and revocation policy so CIBA, personal tokens, and OpenIddict grants cannot drift
- [ ] Migrate one grant at a time under characterization tests and compare old/new claims and token metadata before removing each legacy branch

### 8. Retire the local Pomelo fork when an approved upstream build is available

- [ ] Validate the upstream EF Core 10 provider against the canonical MariaDB schema, migrations, concurrency behavior, and connection-pool settings
- [ ] Run the upstream provider in CI and a production-shaped canary before changing the central package source
- [ ] Remove `.nuget-feed` and the fork-integrity step only after artifact provenance, migration output, and runtime behavior match

## P2 — operational assurance already tracked elsewhere

- [ ] Configure a real shared `IDistributedCache`, set `DistributedCache.RequireShared=true`, and prove DPoP/CIBA/passkey behavior across replicas before scaling out; canonical checklist: `PLAN-PRODUCTION-READINESS.md`
- [ ] Run the OpenID Foundation FAPI 2.0 conformance suite and commission an external review of the custom protocol implementations; canonical checklist: `PLAN-PRODUCTION-READINESS.md`
- [ ] Complete vault named-secret and signing-key phases only through the canonical `PLAN-VAULT.md`, updating that plan's status as phases land

## Closure map

| Evaluation item | Current state | Destination |
|---|---|---|
| C1 plaintext production secrets | code foundation complete; rotation/config-time storage unverified | P0.1 |
| H2 client scope escalation | reserved scopes blocked; shared validation/entitlement/secret contract pending | P0.2 |
| H3 object-level authorization | evaluator seam complete; production policy remains permissive | P0.3 |
| M2 SCIM MFA | optional MFA handler complete; machine-safe per-operation step-up pending | P0.4 |
| M4 SCIM global directory | fail-closed client allow-list complete; partition isolation pending | P0.4 |
| L2 HIBP fail-open | unchanged by design | P1.5 |
| L5 narrow SCIM filtering | `eq` subset remains | P1.6 |
| Architecture: large controller/services | pending | P1.6–P1.7 |
| Architecture: Pomelo fork | still in use | P1.8 |
| Redis/conformance/external audit | code guards exist; operational execution pending | P2 / existing plans |
