# Authorization, SCIM and secret boundaries — remaining work

> **Status:** ACTIVE. Reconciled on 2026-08-09 against the current workspace.
> This document contains only residual work. Implemented foundations and
> canonical handoffs are recorded in
> [`202608092130-security-plan-reconciliation.md`](../activities/202608092130-security-plan-reconciliation.md).

## Delivery constraint

The STS already serves production traffic. Preserve grants, endpoints, users,
clients and integrations through additive schema, compatibility adapters,
shadow decisions, dual-read/backfill and rolling deployment. Enforce each
policy only after telemetry proves the affected cohort is ready.

## P0 — authorization and plaintext boundaries

### Step 1 — reject plaintext configuration after the migration gate

- [ ] Expose redacted resolution provenance from `ISecretStore` so startup can distinguish an approved secret-store value from a legacy configuration fallback without reading or logging the value
- [ ] Add a production-startup gate that rejects legacy database, provider and client-secret fallbacks after the environment explicitly declares migration complete
- [ ] Add a redacted deployment check for machine-specific configuration and `deploy/local/`; report only logical name, source type, owner/state metadata and file permission, never matched values

**Done when:** production can prove that configuration-time credentials came
from the approved secret boundary, startup rejects a reintroduced plaintext
fallback, and the deployment check emits no secret material.

### Step 2 — finish operator-aware client scope and secret authorization

- [ ] Extend the scope-grant boundary to evaluate operator, target client, grant type and requested scopes; preserve `ReservedApiScopes` as a non-bypassable floor and add deployment-defined privileged scopes
- [ ] Define operator-specific scope-minting entitlements and negative decisions for privilege expansion, including stable reason codes and audit records
- [ ] Add `SecretReference` to the Management HTTP create/update contract; retain raw `ClientSecret` only as a deprecated compatibility adapter with a PII-free audit warning and explicit expiry
- [ ] Run the existing validator and the new entitlement decision in shadow mode by client/operator cohort, reconcile expected denials, then enable enforcement and remove the expired plaintext adapter

**Done when:** no operator can grant authority they do not hold, every client
entry point shares the same decision, and new Management requests do not carry
plaintext client secrets.

### Step 3 — persist and enforce object/context ownership

- [ ] Define and persist `ContextId`/ownership for users, clients, scopes, sessions, authorizations, branding and provisioning manifests
- [ ] Introduce `IManagementContextResolver` as the single source of the operator's allowed contexts and use it from the concrete object policy
- [ ] Backfill existing rows into the explicit legacy/global context through an additive, restartable migration with progress telemetry
- [ ] Apply context predicates to every collection query as well as item reads/mutations; propagate the resolved context into every `ManagementResource`
- [ ] Compare legacy/global and context-aware decisions in shadow telemetry, then enforce one resource type at a time while retaining the narrowly assigned break-glass path
- [ ] Add cross-context read, mutation, enumeration, guessed-ID, collection, equal/higher-principal and break-glass audit tests

**Done when:** context changes both item and collection authorization outcomes,
and a generic Management capability no longer implies global object access.

### Step 4 — replace SCIM full-directory trust with operation and partition policy

- [ ] Introduce `IScimOperationAuthorizationPolicy` with separate decisions for read, create/update, password mutation, membership mutation and delete
- [ ] Require MFA for destructive human/delegated operations; require an explicit destructive-operation permission plus mTLS or DPoP for client-credentials callers
- [ ] Add a client-to-partition binding, propagate it through `ScimRequestContext` and backfill existing data into a legacy/global partition
- [ ] Apply partition predicates to every Users/Groups query and mutation, including filters and membership traversal
- [ ] Run dual-read comparison and authorization shadow logging per provisioning client before enforcing partition filters
- [ ] Add cross-partition enumeration, password reset, delete, group nesting and allow-list bypass tests

**Done when:** ordinary SCIM clients cannot enumerate or mutate the global
directory and destructive operations require evidence appropriate to the
caller type.

## P1 — compatibility and maintainability

### Step 5 — make breached-password availability policy explicit

- [ ] Add `BreachedPasswordFailureMode = Allow | Deny | LocalFallback`; retain `Allow` as the compatibility default
- [ ] Add a bounded local compromised-password fallback and cache successful HIBP range responses
- [ ] Add timeout, upstream-error, malformed-response and recovery tests plus degraded-mode metrics
- [ ] Move regulated environments to `LocalFallback` or `Deny` only after audit telemetry characterizes latency and availability

### Step 6 — extract and expand SCIM query processing

- [ ] Extract `IScimFilterParser` and a typed filter AST from `ScimProvisioningService`; translate only validated nodes to parameterized LINQ
- [ ] Add `co`, `sw`, `ew`, logical composition and the multi-valued email/member filters required by current consumers
- [ ] Extract user and group provisioning services, repositories and a shared PATCH applicator
- [ ] Add resource-limit, parser-timeout, invalid-filter, MariaDB translation and interoperability tests
- [ ] Coordinate bulk, sorting and ETag work with `PLAN-PRODUCTION-READINESS.md` instead of creating parallel contracts

### Step 7 — decompose authorization and token issuance without changing routes

- [ ] Extract grant handlers from `AuthorizationController` behind a common issuance request/result contract while leaving current routes as adapters
- [ ] Centralize claim release, scope/resource/audience resolution, token lifetime, sender constraints, audit and revocation so CIBA, personal tokens and OpenIddict grants cannot drift
- [ ] Migrate one grant at a time under characterization tests; compare claims and token metadata before removing each legacy branch

### Step 8 — retire the local provider fork when an approved upstream build exists

- [ ] Validate the upstream EF Core 10 provider against the canonical MariaDB schema, migrations, concurrency behavior and connection-pool settings
- [ ] Run the upstream provider in CI and a production-shaped canary before changing the central package source
- [ ] Remove `.nuget-feed` and the fork-integrity step only after provenance, migration output and runtime behavior match

## Closure dependencies owned elsewhere

The following remain required for production but are not duplicated as active
items in this implementation plan:

- credential/certificate rotation, `pt1` migration, Redis multi-replica proof,
  conformance and external audit:
  [`PLAN-PRODUCTION-READINESS.md`](PLAN-PRODUCTION-READINESS.md).

## Execution order

1. Finish Step 1 before removing any plaintext compatibility path.
2. Deliver Step 2 before enabling stricter client-definition enforcement.
3. Complete Step 3 persistence/backfill before context enforcement.
4. Build Step 4 on the same context model, then migrate SCIM clients by cohort.
5. Execute Steps 5 and 6 independently after P0 has stable telemetry.
6. Execute Step 7 grant by grant under characterization.
7. Execute Step 8 only when an approved upstream artifact is available.

## Final gate

Archive this plan only when every checkbox above is removed through a linked
activity, all operational dependencies have environment evidence, and the
Release build plus focused and full regression suites are green.
