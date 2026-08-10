# Security hardening wave 2 — completed implementation

**Date:** 2026-08-07
**Baseline:** `df308e3` plus the working-tree implementation validated below
**Source plans:** the security remediation plan and `PLAN-SECURITY-HARDENING-WAVE-2.md`

## Outcome

This activity records the security and resilience controls implemented in the
second remediation pass. Compatibility-sensitive policies retain explicit
`Observe | Enforce` gates where immediate production enforcement would risk an
unmeasured client outage. Operational rollout, external conformance and
multi-replica proof remain active plan items; they are not claimed as completed
by this document.

## Issuance and authentication evidence

- Personal-token issuance now has a dedicated policy for client/subject
  eligibility, requested-scope attenuation, authentication freshness, bounded
  lifetime and optional sender constraint.
- Token exchange validates subject-token provenance and rejects missing or
  ambiguous presenter identity when an allow-list is enforced.
- Claim release distinguishes sensitive unmapped claims and exposes a
  compatibility gate for the remaining claim inventory.
- Browser sessions persist and refresh `auth_time`, `amr` and `acr` evidence;
  token projection uses the authenticated-session evidence rather than durable
  user claims.
- CIBA initiation and polling share an explicit client policy, bind the
  authenticated client to pending state, display the binding message during
  approval and disappear as a complete feature unit when disabled.
- mTLS deployment attestation, per-client certificate binding and `cnf`
  projection were added behind explicit configuration.

## Protocol integrity and lifecycle

- DPoP nonces are partitioned by a hashed client/proof context instead of a
  singleton cache key; replay state remains database-authoritative.
- JAR requires the request-object type and bounded `iat`, `exp` and `jti`,
  rejects replay per client, and preserves structured request parameters.
- JARM encryption resolves the recipient key from each client's JWKS and fails
  closed when encryption is required but no usable client key exists.
- Dynamic registration generates client identifiers and high-entropy secrets
  server-side, returns plaintext secret material once, validates the supported
  metadata subset centrally and makes initial access credentials expiring and
  single-use by default.
- Anonymous device-information lookups have a named limiter independent from
  the credential endpoint limiter.
- Server-side cookie tickets use a bounded distributed-cache layer, invalidate
  on revocation and throttle durable last-activity writes while keeping the
  database authoritative.

## Authorization, SCIM and observability

- SCIM scope enforcement and machine-client allow-list enforcement are
  independent. The legacy `RequireAuthorization` option remains only as a
  compatibility alias for scope enforcement.
- Management gained concrete object/context and protected-principal policies,
  including resource-ID validation, tier checks, an audited MFA break-glass
  path and independent `Observe | Enforce` rollout modes.
- Low-cardinality, PII-free counters expose policy decisions and compatibility
  fallbacks through `Sufficit.Identity.Security` without tagging subject,
  client, token or resource identifiers.
- Local redirect handling delegates to the canonical validator, including
  repeated encoding, ambiguous separators, `PathBase` and preserved query
  handling.
- OAuth resource validation no longer has a global disable path: configured
  MCP resources are registered as both supported resources and audiences, and
  unregistered resource indicators are rejected with `invalid_target`.
- Management grant parsing now accepts only known RFC/OpenIddict grant forms,
  maps token-exchange explicitly and rejects unknown values before persistence.
- Reserved security scopes now flow through one `IReservedScopePolicy` shared
  by provisioning, Management CRUD and DCR, preventing ordinary registration
  paths from minting administrative scopes.
- The CIBA route annotation was corrected to distinguish OIDC CIBA Core from
  RFC 9126 (PAR).
- Dynamic authorization-code registration now requires PKCE for confidential
  and public clients alike; a client secret does not replace the verifier
  binding.
- Account recovery, external login, CIBA login hints and passkey lookup now
  use a normalized-email policy that refuses ambiguous duplicate rows instead
  of selecting an arbitrary recovery target.
- Browser-session `sid` reuse now requires both the current subject and a
  matching durable `oidcusersessions` row. Stale cookies, account switching
  and missing persistence evidence mint a fresh identifier.
- Machine-to-machine authorizations no longer project a client-credentials
  subject as an Identity user. The Management UI now shows those grants as
  service authorizations instead of probing `/users/{client_id}` and creating
  misleading `user_not_found` audit events.
- Sensitive unmapped claim suppression emits low-cardinality security-decision
  telemetry without recording claim values.
- High-sensitivity persisted claims (security/password/MFA material) are denied
  even while the compatibility bridge for the remaining unmapped claim
  inventory is still enabled.

## Key, release and migration boundaries

- Signing and encryption certificates support ordered active/retiring overlap;
  optional purpose separation prevents reuse of one active certificate for both
  roles.
- Privileged release preparation moved to a root-owned bootstrap helper. The
  runtime preflight is read-only, unprivileged and fail-closed; release contents
  are immutable to the service account.
- The systemd unit no longer ignores preflight failures and applies a
  least-privilege sandbox with an explicit runtime write path.
- A dedicated `--migrate-only` execution mode and hardened oneshot systemd unit
  apply migrations under a MariaDB advisory lock. The production HTTP process
  rejects legacy automatic migration.
- The canonical empty-database SQL was regenerated through the new
  `AddManagementClientDrafts` migration, keeping the checked-in schema contract
  synchronized with EF Core.
- The production Docker restore is locked to the committed package graph, CI
  builds the production image, and NuGet source mapping restricts the temporary
  provider fork to its private feed.
- `DeploymentTopology` is explicit (`SingleReplica`, `Clustered`,
  `BehindTrustedProxy` or `ClusteredBehindTrustedProxy`) and startup validation
  derives the required shared-cache, trusted-proxy, rate-limit and issuer
  contract for clustered/proxy modes.
- Vault envelope encryption now depends on the `IVaultKeyEncryptionKeySource`
  boundary, retaining Data Protection as the compatibility implementation and
  leaving external KMS/HSM custody as the next deployment-specific adapter.
- Added `docs/migration/sql/082-add-security-hardening-state.sql` for metrics,
  SSF hardening, atomic CIBA/DPoP state and management drafts, with migration
  markers and a twice-run idempotency rehearsal wired into CI.
- Added `docs/migration/sql/083-enforce-normalized-email-uniqueness.sql`, which
  produces only hashed duplicate-email counts, aborts closed while collisions
  remain, and adds a nullable provider-compatible unique index once the
  operator cleanup gate is satisfied; it never chooses or deletes an account.
- Documented the operator cleanup gate in `docs/runbooks/RUNBOOK-DEPLOYMENT.md`:
  account IDs are handled only through the audited administration workflow and
  the SQL script is rerun until the redacted report is empty.
- Removed the placeholder external image host and broad WebSocket schemes from
  the default CSP; rendered-UI origin inventory and enforce-mode calibration
  remain an operational gate.
- Added an explicit database transport policy with verified-TLS and audited
  private-socket modes, including CA-path validation and positive/negative
  startup-contract tests. Production selection remains deployment-specific.
- CI now checks that every EF migration has canonical or additive SQL coverage;
  both additive hardening scripts are executed twice against the MariaDB
  service.

## Concurrent Management integration reconciled

The Management application configurator introduced protected, expiring client
drafts and renamed the operator-facing concept from “cliente” to “aplicação”.
The migration history, canonical SQL and routing assertions were reconciled
with that flow without discarding the concurrent UI/service changes.

## Validation evidence

- `dotnet restore Sufficit.Identity.sln --locked-mode`: successful for all 12
  projects.
- `dotnet build Sufficit.Identity.sln --no-restore -warnaserror`: 0 warnings,
  0 errors.
- Focused regression suites for topology, database transport, DCR PKCE,
  persisted-session binding, account lookup, MCP resources and management grant
  parsing also passed with zero failures.
- `dotnet test Sufficit.Identity.sln --no-restore`: 498 passed, 0 failed; the
  existing public-UI localization test remains explicitly skipped.
- Shell syntax validation passed for deployment helpers.
- `systemd-analyze verify` accepted the unit syntax; expected diagnostics on
  the development host were limited to production-only executable paths that
  are installed by `helpers/install.sh`.
- `git diff --check`: clean before documentation reconciliation.

## Residual work retained in active plans

- Finish the physical extraction of Management DTOs/interfaces into
  Application Abstractions and remove external/dual compilation.
- Complete the full shared client-definition lifecycle across provisioning,
  Management and DCR, including ownership/adoption and protected update,
  delete and secret rotation.
- Perform production inventories, cohort enforcement, canaries and rollback
  rehearsals for compatibility-gated policies.
- Prove Redis/MariaDB behavior across replicas and run browser, OAuth/OIDC,
  FAPI, CIBA and SSF conformance/fault-injection suites.
- Add durable security-audit outbox/alerts, broader distributed abuse
  protection, KMS/HSM key custody, verified database transport and the planned
  MariaDB platform upgrade.
