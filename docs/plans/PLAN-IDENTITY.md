# PLAN — Sufficit Identity

> **Status:** ACTIVE — this is the only plan in the repository, consolidated
> from seventeen on 2026-09-19 and verified against the code, not against the
> plans it came from:
> [`202609191200`](../activities/202609191200-plan-consolidation.md).
>
> **Rule:** finished work leaves this file and becomes an activity under
> `../activities/`. Nothing is recorded here as done.
>
> **Section ids are stable from 2026-09-19 on.** A delivered section leaves a
> gap instead of renumbering the rest, because activities, commits and other
> documents cite these ids — `conformance/README.md` points at B9. Sections C,
> D and F were renumbered before this rule, so an activity written earlier that
> day may cite an id that now names a different section; its title says which
> work it was.

Twelve plans had grown around three security evaluations, two console
redesigns and one production rollout. They overlapped badly: the same claim
inventory was owned by three of them, object/context ownership by three more,
and CSP enforcement by four. An item that three documents each describe
slightly differently is an item nobody can close. This file states each one
once, under the boundary it actually belongs to, and names the file or type
that already exists where the work is partially built.

Items marked **(operational)** need a human acting against real infrastructure,
clients or data. No amount of code closes them, and they are what actually
gates production. Items marked **(blocked)** state what blocks them.

## Delivery constraint

The STS serves production traffic. Preserve grants, endpoints, users, clients
and integrations through additive schema, compatibility adapters, shadow
decisions, dual-read/backfill and rolling deployment. Enforce a policy only
after telemetry proves the affected cohort is ready. A feature that cannot meet
its security invariant stays disabled rather than advertising partial
assurance. No production feature, grant, endpoint, client type or user journey
may be removed as a shortcut to closing an item.

## Operational calendar

Dated production actions, earliest first. Each links to the section that owns
it; tick it there, then drop the line here.

| When | Action | Owner |
|---|---|---|
| ~2026-11-03 | Delete the 10 disabled underscore client ids if they issued no token since 2026-10-27 | [`202610271500`](../activities/202610271500-hyphenated-client-ids.md) |
| ~2026-11-04 | Read the observed scope-grant rows; set `ClientScopeGrants:Mode=Enforce` | A2 |
| after the client-id cleanup | Remove the legacy client/scope acceptance in endpoints (`LegacyClientId`) and background (`Legacy*`) | [`202610271500`](../activities/202610271500-hyphenated-client-ids.md) |
| from 2026-11-20 | Drop `certificate.pfx` and `certificate-old.pfx` from `EncryptionPaths` | C2 |
| when the August agent authorizations stop refreshing | Remove the `sufficit_ai_openai_bridge` scope and permission | [`202610271500`](../activities/202610271500-hyphenated-client-ids.md) |
| before 2027-04-30 | Migrate every `client_secret_plaintext_deprecated` caller to `secretReference`; the adapter refuses after that date | A2 |
| open | Inventory the production provisioning manifests and adopt existing clients explicitly | A2 |

Every enforcement change follows the same sequence: add the abstraction and
telemetry without changing the decision; inventory what would be affected;
provide a compatibility adapter or backfill; enable by bounded cohort; retain
an audited rollback switch for one release window; remove the compatibility
path only when telemetry reaches zero legacy use.

---

## A. Authorization and trust boundaries

### A2 — Operator-aware client scope and secret authorization

- [ ] **(operational, ~2026-11-04)** Reconcile the observed denials (audit
  `reasonCode like 'scope_grant_%'`, `operationOutcome = 'observed'`), then set
  `ClientScopeGrants:Mode=Enforce` on the three nodes
- [ ] **(operational, before 2027-04-30)** Migrate plaintext-secret
  callers (`client_secret_plaintext_deprecated`) to `secretReference` and
  remove the adapter after `ClientSecrets:PlaintextExpiresAtUtc`
- [ ] **(operational)** Inventory the real production manifests and adopt
  existing managed clients explicitly before enabling client-definition
  enforcement
- [ ] Bring `/secret/rotate` and `/credentials` onto `secretReference`; they
  still accept an operator-supplied secret

Decision, contract and the production privileged-scope list:
[`202610281800`](../activities/202610281800-operator-scope-grant.md).

**Done when:** no operator can grant authority they do not hold, every client
entry point shares one decision, and new Management requests carry no plaintext
client secret.

### A3 — SCIM operation policy

The directory a SCIM client sees is the deployment's whole directory, by the
same product decision as the no-tenant boundary (`ARCHITECTURE-MANAGEMENT-AUTHORIZATION.md`) — partitioning it would be the row-level tenant
boundary that decision rejected. What SCIM lacks is a decision per
*operation*: today a client that may provision may also delete.

- [ ] **(operational, gated: SCIM is off in production)** Inventory the provisioning clients, grant
  `scim.destructive` to the ones that legitimately delete or reset passwords,
  bind their tokens, then set `Scim:OperationPolicyMode=Enforce`

Per-operation decision, in `Observe`, and what it was built on:
[`202609201900`](../activities/202609201900-scim-per-operation.md).

**Done when:** a client allowed to provision cannot delete or reset a password
without being separately permitted to, with evidence appropriate to its type.

### A4 — Step-up enforcement and one MFA evidence policy

- [ ] Finish the single evidence policy. Neither side is unified yet: SCIM
  keeps its own reader (`ScimServiceCollectionExtensions.cs`, own method set
  and `HasMfaEvidence`) beside `MfaEvidencePolicy`, and `amr` is still set in
  several places (interactive sign-in, identity-assertion grants, provisioning
  and operator tokens, development endpoints)
- [ ] End-to-end tests proving a real MFA login satisfies Management and SCIM
  policies, and that a stale session cannot mutate credentials

`ReauthenticationController` and `IAuthenticationContextProjector` already
provide the ceremony and the projection into codes and tokens.

**Decided 2026-09-20 (owner):** a remembered-MFA device satisfies Management
but does not mint credentials, and the ceremony runs at the authorization
endpoint rather than in each relying party.
[`202609200800`](../activities/202609200800-remembered-second-factor.md),
[`202609201100`](../activities/202609201100-authorize-step-up.md),
[`202609201300`](../activities/202609201300-acr-values.md).

## B. Token issuance and claim release

### B3 — Token exchange provenance and delegation

- [ ] Let the holder of a DPoP-bound subject token exchange it. It fails
  closed today: `ValidateDpopAccessTokenProof` checks `ath` against the
  reference token's resolved payload (`context.Token`) because the token
  endpoint has no `AccessToken`, so even the right key and a correct `ath`
  are refused; once fixed, the same proof is checked again in
  `TokenGrantDispatcher` and its replay guard may refuse it. Pinned by the
  skipped test in `TokenExchangeSubjectTokenTests`. No production exchange
  presents a DPoP-bound subject token today

Built on: exchange provenance, actor allow-list and `act` chains (`1d04868`),
[`202609200500`](../activities/202609200500-delegation-depth.md) (delegation
depth) and
[`202610042300`](../activities/202610042300-delegated-device-credentials.md)
(delegated device credentials, off by default). `Observe` for provenance is
only a migration valve reported by the posture check.

### B5 — CIBA trust boundary completion

- [ ] Run CIBA interoperability/conformance and approval-fatigue abuse tests
  before enabling additional clients

Built on: [`202609201500`](../activities/202609201500-ciba-initiator-and-rolling-deploy.md)
(`ICibaClientPolicy`, bound `binding_message`, `CibaProtocolFeature`).

### B9 — FAPI 2.0: the one accepted conformance failure **(deferred by decision)**

`par-attempt-to-use-expired-request_uri` expects the error to reach the client
as a redirect carrying `invalid_request_uri`; the server refuses the expired
`request_uri` on its own error page. OpenIddict drops the request while
extracting it, before any redirect URI has been resolved — the request carries
only `client_id` and `request_uri` — so there is nowhere to send the error.

A handler on
`ApplyAuthorizationResponseContext` does find the client and its single
registered URI, but nothing downstream honours it:
`Authentication.AttachRedirectUri` clears a redirect URI it did not validate
itself, `InferResponseMode` derives the mode from a `response_type` this request
never had, and the local error response is produced regardless.

- [ ] Resolve the client's registered redirect URI before the refusal, and only
  when the registration leaves no ambiguity — **revisit only if a client ever
  needs the machine-readable error.** No authorization is granted and the user
  is told either way.

The accepted warning and skips (`FAPIEnsureServerConfigurationDoesNotSupport`
`RefreshToken`, the unimplemented `claims` parameter,
`ensure-signed-client-assertion-with-RS256-fails`, OpenIddict's `oi_tkn_id`/
`oi_au_id`) are documented with reasons in `conformance/config/`.

---

## C. Secrets, keys and transport

### C1 — Vault production enablement and rotation

- [ ] **(operational)** Separate database-reader authority from KEK authority
  in production
- [ ] Test a re-wrap racing a data-key rotation on another replica (loss,
  old-version decrypt and restore are covered:
  [`202610232000`](../activities/202610232000-vault-kek-rotation.md))

Built on: [`202610231900`](../activities/202610231900-vault-kek-escrow.md)
(KEK escrow). Procedure: `../runbooks/RUNBOOK-VAULT.md`.

### C2 — Signing and encryption key separation

Certificate separation: [`202610231600`](../activities/202610231600-encryption-certificate-separation.md).

- [ ] **(operational, from 2026-11-20)** Drop `certificate.pfx` and
  `certificate-old.pfx` from `EncryptionPaths`: the last valid token encrypted
  with them expires 2026-11-19 17:39 UTC
- [ ] Introduce purpose-separated protocol signing/encryption keys with
  active/retiring overlap, stable `kid`, JWKS rotation and a KMS/HSM-backed
  production provider
- [ ] Separate token, Data Protection and TLS key material; validate the
  compromise and rollback procedures
- [ ] **(operational)** Audit and rotate any production signing material that
  may have been created through the legacy helper path, recording only
  thumbprints and versions — never keys or passwords
- [ ] **(operational)** Inventory certificates, prove the signing/KEK
  separation and execute a restore/disaster-recovery rehearsal

### C4 — Verified transport everywhere

- [ ] **(operational)** Select `RequireVerifiedTls` — or the audited
  `PrivateSocket` exception — in each production deployment, after the CA or
  socket is provisioned. Today the connection string declares no `SslMode`
  and goes through the local proxy (`db-proxy-local`)

An explicit transport policy already validates VerifyCA/VerifyFull or a
UnixSocket exception; production still has to choose the mode.

### C5 — Legacy credential inventory and rotation **(operational)**

- [ ] Inventory and rotate the legacy database and provider credentials and
  certificates, migrate `deploy/local/` to the approved secret store, and
  attach a redacted manifest with owner, version, state and retirement date

---

## D. Production posture and configuration

### D1 — CSP from telemetry to enforcement

- [ ] Make the report-only rollback switch bounded: `AcknowledgeReportOnly` has
  no expiry (reports already strip query and userinfo)

Procedure: [`RUNBOOK-CSP-CALIBRATION.md`](../runbooks/RUNBOOK-CSP-CALIBRATION.md).

---

## E. Administration console and UI

### Domain limits that bind every item in this section

- A user claim is a **generic** attribute of the provider. Sufficit's roles,
  directives and business rules do not enter the identity provider.
- An application claim is released only through an allow-list with explicit
  destinations — never copied wholesale into a token.
- A manifest-managed client is owned by its manifest. The console shows the
  ownership and refuses the mutation; it never edits it behind the manifest's
  back.
- No secret, token, authorization or manifest property is ever copied into a
  list, a URL, a draft, a log or an audit record.

### E2 — Application lifecycle: credentials and cloning

- [ ] Integrate `SecretReference` and the vault into the console's credential
  surface
- [ ] Explicit rotation behind its own capability
- [ ] Show only "credential configured", its origin and a safe date — never the
  value or a hint derived from it
- [ ] Cloning that copies no secret, token, authorization or operational state
- [ ] Confirm impact and revoke authorizations/tokens only when the policy
  requires it
- [ ] Document rollback and recovery
- [ ] Define typed application claims and properties with an allow-list and
  destinations

### E3 — Application operation and scale

- [ ] Per-application metrics connected to the existing metrics module
- [ ] Audit timeline filtered by client ID
- [ ] Session and authorization revocation actions in the application's context
- [ ] Volume test with thousands of clients

### E4 — Application advanced settings (only where enforcement is real)

- [ ] Typed public metadata (`description`, `client_uri`, `logo_uri`)
- [ ] Application claims with allow-list and destinations, through a release
  policy that sees client, grant, scopes, resources and destination and is
  shared by the grants and the privileged mints ([`202610240200`](../activities/202610240200-no-unified-issuance-service.md))
- [ ] Advanced properties with a namespace and reserved keys
- [ ] Per-client DPoP/JAR/CIBA/FAPI configuration only where the runtime
  actually honours it
- [ ] New profiles only when each has a validator, an explanation and tests

Per-application access, identity and refresh token lifetimes already exist on
create and update (`ClientTokenLifetimePolicy`), as does per-client PAR.

### E6 — Mobile-first validation and rollout

- [ ] Deliver and test the client configurator at 320–430 px first, then tablet
  and desktop
- [ ] Validate keyboard, focus, virtual keyboard, deep link, F5 and concurrency
  on the creation and edit flows
- [ ] **(operational)** Publish the update capability per deployment and
  validate the real clients

`ManagementConsoleResponsiveTests` already checks every console page at 320,
360, 390 and 430 px.

### E7 — Pluggable UI, phases 2–5

Phase 2 is half-built: `UiModuleDescriptor`/`IUiModuleRegistry` version the
modules and `UiCompositionValidation` rejects duplicates and incompatible
versions at startup.

- [ ] **Phase 2:** semantic endpoint registration (module-declared routes
  rather than hard-coded paths); an official standalone embedded-composition
  executable, not just the API host
- [ ] **Phase 3 — remote Management UI:** publish the complete versioned
  Management HTTP contract (BFF API spec); a standalone BFF host with code flow,
  PKCE and server-side tokens; end-to-end authorization/CSRF/logout/
  token-leakage tests
- [ ] **Phase 4 — remote public interaction:** specify and threat-model the
  opaque interaction protocol (login, consent, device, logout); durable
  distributed interaction state with replay protection; replace hard-coded UI
  redirects with semantic endpoint resolution; end-to-end coverage of login,
  external, MFA, passkeys, consent, logout, device and registration
- [ ] **Phase 5 — third-party SDK:** templates, examples, packages and a
  compatibility policy; a conformance kit published and run in CI; documented
  trusted-package approval and remote-provider registration

### E8 — Accessibility and localization

- [ ] WCAG 2.2 AA accessibility audit of both embedded UIs

---

## F. Platform and architectural debt

### F1 — Posture contributors inside the feature contract

`IProtocolFeature` (`sts/Features/`) already gives each optional protocol its
own `Validate`, `ConfigureServices`, `ConfigureServer`, `ConfigureValidation`,
`ConfigureDiscovery` and `RuntimeCapabilities`, across eleven features. One
hook from the original proposal is missing.

- [ ] Add the posture contributor to the feature contract, so a feature owns
  its production findings the same way it owns its discovery metadata (today
  the findings live in four separate `IProductionPostureContributor`
  implementations, one of which carries every STS finding regardless of which
  feature owns the setting — which is how the coverage fell behind the
  configuration surface in the first place)

### F2 — One management operation executor

- [ ] Replace the `DemandAsync`/`TryWriteAuditAsync` pair repeated across about
  thirty management files with a `ManagementOperationExecutor`
- [ ] Remove the duplicated `ManagementOptions` (STS × Abstractions)

`ManagementOperationGuard` already unified the authorize-and-audit decision and
made "audit this refusal" an explicit argument at the call site; the executor is
the next step up.

### F3 — SCIM decomposition and query processing

- [ ] Extract `IScimFilterParser` and a typed filter AST from
  `ScimProvisioningService`; translate only validated nodes to parameterized
  LINQ. Filtering is two regexes today — `EqualityFilterRegex` and
  `MemberPathFilterRegex` — so equality is all a caller gets
- [ ] Add `co`, `sw`, `ew`, logical composition and the multi-valued
  email/member filters current consumers need
- [ ] Extract the repositories and promote the PATCH applicator to a shared
  one; `NormalizePatchOperation`/`ValidatePatchRequest` are private statics in
  `ScimProvisioningService.Support.cs`. The service is already split into
  `.Users`, `.Groups` and `.Support`
- [ ] Add bulk, sorting and ETags — intentionally unadvertised today; enable per
  demand, from this same extraction rather than a parallel contract
- [ ] Tests: resource limits, parser timeout, invalid filter, MariaDB
  translation, interoperability

### F4 — Sessions off the per-request write path

- [ ] Introduce a cancellation-aware session repository with a shared cache and
  explicit revocation invalidation. `OidcUserSessionTicketStore` already gates
  the activity write behind an interval, so the unbounded per-request write is
  gone; the repository, the shared cache and the cancellation contract are not
- [ ] Define database/cache outage behaviour so a temporary storage failure
  neither creates an unbounded login outage nor accepts revoked sessions
  indefinitely
- [ ] Multi-replica consistency, stale-cache, failover and cancellation tests

### F5 — Schema migration out of the web process

- [ ] Remove the web process's migration responsibility now that deployment
  automation has the migrator. `AutoMigrate` already defaults to `false`, and
  `AllowedDatabaseNames` guards it, so this is about deleting the path rather
  than turning a switch
- [ ] Test two-replica startup, failed migration, retry and old-binary rollback
  against additive schema

`helpers/sufficit-identity-migrator.service` and the
`GET_LOCK('sufficit_identity_schema_migrator')` advisory lock already exist.

### F6 — Provider fork retirement and provenance

- [ ] Validate the upstream EF Core 10 provider against the canonical MariaDB
  schema, migrations, concurrency behaviour and connection-pool settings
- [ ] Run the upstream provider in CI and in a production-shaped canary before
  changing the central package source
- [ ] Remove `.nuget-feed` and the fork-integrity step only after provenance,
  migration output and runtime behaviour match
- [ ] If the fork has to remain, publish it under a Sufficit-owned package ID
  with repository URL, commit, license, deterministic-build and SBOM metadata,
  build it in CI from a pinned commit and compare the produced artifact hash —
  the checksum of an opaque committed package is not provenance
- [ ] Run vulnerability and license scanning against the source and the final
  dependency graph

### F7 — Supported MariaDB baseline

CI and the provider configuration are pinned to MariaDB 10.4.34.

- [ ] Select a currently supported MariaDB LTS target compatible with the
  provider
- [ ] Run both versions in CI: canonical schema, additive rehearsal, grants,
  concurrency, locking, collations, index-width behaviour
- [ ] **(operational)** Canary production-shaped traffic, migrate replicas and
  backups, retain 10.4 compatibility until the cutover completes
- [ ] Remove the 10.4 lane only after rollback and restore rehearsals succeed on
  the target

### F9 — Unambiguous normalized email identity

- [ ] Add registration, SCIM update, email change, login and recovery race tests

Recovery, external-login, CIBA and passkey lookups reject ambiguous normalized
matches, and `EmailIndex` is unique since 108
([`202610231300`](../activities/202610231300-schema-parity.md)).

### F10 — Dynamic client registration lifecycle

- [ ] Implement protected read, update, delete, secret rotation and the audit
  lifecycle
- [ ] Retain caller-supplied secrets only behind a deprecated audited adapter
  during migration, with an entropy floor and a deadline
- [ ] Align the operator-managed application lifecycle and secret references
  with E2
- [ ] **(decision)** DCR is **on** in production for anonymous public clients
  (`Dcr:Enabled=true`, `RequireInitialAccessToken=false`, chosen in
  [`202609132250`](../activities/202609132250-deploy-evaluation-remediation.md)).
  Either require an initial access token until the lifecycle, abuse controls
  and interoperability tests are complete, or record the accepted risk

Server-generated IDs and secrets, expiring single-use initial access tokens,
central metadata validation and public-client PKCE are already covered.

### F11 — Breached-password availability policy

- [ ] **(operational)** Move to `FailClosed` once the
  `breached_password_check` telemetry characterises latency and availability
  (production runs `LocalFallback`:
  [`202609201200`](../activities/202609201200-breach-check-in-production.md),
  [`202609201700`](../activities/202609201700-breached-password-fallback.md))

### F12 — GCM budget

- [ ] Auto-rotate the DEK at its budget, or drive rotation from a durable
  counter. `VaultCryptographyTelemetry` warns at 80% and logs critical at 100%,
  but it counts **per process** in a `ConcurrentDictionary`, so three replicas
  reach the real budget while each reports a third of it. Automatic rotation is
  disabled on purpose until the aggregated metric exists

### F14 — Security-critical protocol annotations

- [ ] Remove comments claiming a guard is unconditional where composition makes
  it conditional
- [ ] Review security comments against executable tests and delete the
  historical "item fixed" narratives that no longer describe current behaviour

### F15 — Multiple email addresses per account

Design: [`ARCHITECTURE-ACCOUNT-EMAILS.md`](../architecture/ARCHITECTURE-ACCOUNT-EMAILS.md).
Motivated by [`202610301530`](../activities/202610301530-nilza-username-empresarial.md),
where a primary address had to be swapped in the database and the old one was lost.

- [ ] Migration 110 `useremails` (primary mirrored as a row, unique normalized
  address) with backfill from `users.Email`
- [ ] `IAccountEmailService` as the only writer; dual-write `users.Email`;
  `UpdateProfile` email change routed through it
- [ ] Parity check between `users.Email` and the primary row as a posture finding
- [ ] `AccountLookupPolicy` reads confirmed rows only, behind a flag
- [ ] Management routes under `api/users/{id}/emails` (`identity.users.update`)
  and console page
- [ ] Self-service `/manage/emails` with confirmation link, recent
  authentication and notification of the previous primary
- [ ] SCIM full `emails[]` mapping per client trust
- [ ] Race and non-resolution tests listed in the design (extends F9)

---

## G. Observability, conformance and cutover

### G1 — Security decisions must be observable

- [ ] Emit structured, PII-safe events for issuance policy, actor chain,
  personal tokens, step-up, replay, egress denial, key rotation and
  authorization denial
- [ ] Deliver the security audit through a durable outbox, with a defined
  retention, integrity and access-control policy
- [ ] Alert on compatibility fallback, plaintext/TLS warnings, replay pressure,
  unexpected public origin and expiring keys

### G2 — Conformance and certification

OIDC Basic and FAPI 2.0 run nightly:
[`202609171900`](../activities/202609171900-openid-conformance-gate.md).

- [ ] Run the SSF conformance suite for the capabilities announced
- [ ] **(operational)** Submit the applicable profiles to formal certification
- [ ] **(operational)** Commission an external audit of DPoP, CIBA, JARM, JAR,
  mTLS, token exchange, SSF and the vault; fix and retest every blocking finding
- [ ] **(operational)** Commission an independent review of the custom
  protocol/security code

### G3 — Distributed, browser and fault verification

- [ ] Browser tests for passkey registration/login, 2FA, consent, CSP and
  step-up on the supported desktop and mobile engines
- [ ] Real MariaDB/Redis concurrency tests, feature-off 404 tests,
  host-poisoning tests and key/cache/database fault injection
- [ ] **(operational)** Verify the egress firewall and every approved outbound
  target in the production topology

### G4 — Legacy cutover operational gates **(operational)**

Gates already passed:
[`202608011820`](../activities/202608011820-legacy-cutover-db-provider.md),
[`202610221630`](../activities/202610221630-plan-reconciliation.md).

**Clients**

- [ ] Every active client has an assigned owner and a documented final state
- [ ] Confidential clients have newly issued, post-migration credentials
- [ ] Redirect, logout and CORS allow-lists verified per client
- [ ] Token format validated by every resource server (reference vs JWT)

**Keys and infrastructure**

- [ ] JWKS overlap and rotation tested — old and new keys visible during the
  transition
- [ ] Proxy and forwarded headers verified end to end
  (`X-Forwarded-Proto`/`Host`, TrustedProxies)

### G5 — Confirmed-email rollout **(operational)**

- [ ] Decide on the accounts with an unconfirmed email that **were** used (a
  token in the last 90 days): confirm them in bulk or leave them to
  reconfirmation — the unused ones are purged automatically

### G6 — Forward-looking protocol work

Deliberately after everything above; none of it is required for production.

- [ ] FAPI 2.0 Advancing Profile (needs encrypted request objects beyond JAR)
- [ ] Rich Authorization Requests (RAR — `authorization_details`)
- [ ] OpenID Federation (entity statements, trust chains)
- [ ] SSF durable outbox/retry state (persistent delivery guarantees beyond
  best-effort)

### G7 — Coordinated disclosure **(operational)**

- [ ] Decide on coordinated disclosure before adding the confidential review
  identifier or any reproduction detail to this public repository

---

## Execution order

1. **A2** — reconcile the observed scope grants and enforce (~2026-11-04)
2. **C1** — the re-wrap race test and the reader/KEK authority split
3. **B3, B5** — DPoP-bound subject token exchange and CIBA abuse tests
4. **E6** — the mobile pass on the creation and edit flows
5. **E2, E4, E7, F1–F15** — as capacity allows, in the order the team prefers;
   none of them blocks another
6. **G** — conformance, audit, cutover and rehearsals, continuously, and G4
   before anyone calls the legacy migration finished

What has already been delivered is in `../activities/`, dated, not here: this
file is what is left to do.

## Closure criteria

- [ ] Every item above is either implemented and regression-tested, or linked
  to an explicitly accepted risk with an owner and an expiry date
- [ ] Observe-mode telemetry shows no unexplained future denials for the cohort
  being enabled
- [ ] No production feature, grant, endpoint, client type or user journey was
  removed to close an item
- [ ] Fresh-install and additive-upgrade schemas are equivalent at HEAD
- [ ] CI covers the supported database versions, a locked restore/container
  build, the security-boundary tests and secret scanning
- [ ] Every operational item has environment evidence in the format of
  [`RUNBOOK-PRODUCTION-EVIDENCE.md`](../runbooks/RUNBOOK-PRODUCTION-EVIDENCE.md)
- [ ] Release build plus the focused and full regression suites are green
