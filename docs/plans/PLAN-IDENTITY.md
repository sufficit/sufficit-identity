# PLAN — Sufficit Identity

> **Status:** ACTIVE — this is the only plan in the repository.
> **Consolidated:** 2026-09-19, from twelve separate plans, each reconciled
> against the working tree before its items were carried over.
> **Verified against the code on 2026-09-19.** Every item was checked against
> the working tree, not against the plan it came from. Five turned out to be
> already delivered and were deleted: the protocol feature registrar and the
> feature-unit composition (`IProtocolFeature` and its eleven features), the
> `#if APPLICATION_CONTRACTS` dual compilation, the systemd sandboxing, and
> CIBA answering 404 when disabled. Four more were rewritten because the code
> had moved further than the item admitted — SCIM extraction, session activity
> writes, `AutoMigrate`, and the breached-password failure mode.
>
> **Re-verified on 2026-09-20 by reading the code, not by searching for
> symbols.** The first pass trusted that a missing type meant missing work,
> and it was wrong often enough to matter: the tenant machinery (A1) had been
> removed by decision, JAR/JARM (B6) was built and only unproven, the DPoP
> nonce (B4) had the right store written and the wrong one registered. This
> pass corrected A3, A4, B3, B5, C4, D1, D6 and E4 to what the code actually
> does, and marks one item **(decision)** — A4's remembered-MFA question,
> where an evaluation asked the plan to reverse a deliberate fix.
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

Every enforcement change follows the same sequence: add the abstraction and
telemetry without changing the decision; inventory what would be affected;
provide a compatibility adapter or backfill; enable by bounded cohort; retain
an audited rollback switch for one release window; remove the compatibility
path only when telemetry reaches zero legacy use.

---

## A. Authorization and trust boundaries

### A1 — Protected principals and operator entitlements

**There is no tenant or context boundary inside a deployment, by product
decision** (`cd67f51`, 2026-08-15; `ARCHITECTURE-MANAGEMENT-AUTHORIZATION.md`,
"No tenant boundary inside a deployment"). One deployment serves one
organization; isolation between organizations is one deployment each, with its
own database. Object-level authorization is capability, MFA step-up and
protected principals, and the architecture says not to reintroduce tenant data
or authority without a new decision.

The first consolidation of this plan carried over five items from the
2026-08-07 evaluation (V-19, "tenant-aware Management authorization") that
predate that decision — a persisted `ContextId` per object, an
`IManagementContextResolver`, a backfill into a global context, context
predicates on every query, and context shadow telemetry. They were exactly the
machinery the decision removed, and they are gone from here. What V-19 asked
for that still applies under the current contract is below.

- [ ] Separate operator entitlements from the roles and scopes issued to
  managed identities
- [ ] Test that break-glass through a claim, session or authorization is
  audited the same way as break-glass through a user (the equal/higher tier
  matrix across every capability that reaches a user is covered)

Protected principals now cover every mutation that reaches a user, delivered on
2026-09-19 —
[`202609192300-protected-principals-everywhere.md`](../activities/202609192300-protected-principals-everywhere.md).

**Done when:** no Management capability lets an operator change or revoke
anything belonging to a principal of equal or higher tier without break-glass.

### A2 — Operator-aware client scope and secret authorization

- [ ] Extend the scope-grant boundary to evaluate operator, target client,
  grant type and requested scopes; keep `ReservedApiScopes` a non-bypassable
  floor and add deployment-defined privileged scopes
- [ ] Define operator-specific scope-minting entitlements and negative
  decisions for privilege expansion, with stable reason codes and audit records
- [ ] Add `SecretReference` to the Management HTTP create/update contract;
  retain raw `ClientSecret` only as a deprecated compatibility adapter with a
  PII-free audit warning and an explicit expiry
- [ ] Run the validator and the new entitlement decision in shadow mode by
  client/operator cohort, reconcile expected denials, enforce, then remove the
  expired plaintext adapter
- [ ] **(operational)** Inventory the real production manifests and adopt
  existing managed clients explicitly before enabling client-definition
  enforcement

`IClientDefinitionValidator`, `IReservedScopePolicy` and
`IClientScopeGrantPolicy` already govern the three client-definition entry
points with `Observe`/`Enforce` rollout; what is missing is the operator
dimension and the manifest adoption pass.

**Done when:** no operator can grant authority they do not hold, every client
entry point shares one decision, and new Management requests carry no plaintext
client secret.

### A3 — SCIM operation policy

The directory a SCIM client sees is the deployment's whole directory, by the
same product decision as A1 — partitioning it would be the row-level tenant
boundary that decision rejected. What SCIM lacks is a decision per
*operation*: today a client that may provision may also delete.

- [ ] Introduce `IScimOperationAuthorizationPolicy` with separate decisions for
  read, create/update, password mutation, membership mutation and delete
- [ ] Require MFA for destructive human/delegated operations; require an
  explicit destructive-operation permission plus mTLS or `private_key_jwt`/DPoP
  for client-credentials callers
- [ ] Tests: per-operation refusal, password reset, delete and group nesting

Already in place, verified 2026-09-20: `ScimOptions.RequireAllowedClient`
(default `true`), `ClientPolicyMode` `Observe`/`Enforce`, `RequireScope`
independent of the client decision, `RequireMfa`, the
`ScimAuthorizationAuditFilter` auditing both decisions, and posture findings
`scim-client-allow-list-disabled`, `scim-client-policy-observe`,
`scim-mfa-disabled` and — since 2026-09-20 — the advisory
`scim-client-allow-list-empty`.

**Done when:** a client allowed to provision cannot delete or reset a password
without being separately permitted to, with evidence appropriate to its type.

### A4 — Step-up enforcement and one MFA evidence policy

- [ ] **(operational)** Change credential-mutation step-up from `Audit` to
  `Enforce` after current sessions and UI flows pass canary checks
- [ ] Finish the single evidence policy: the readers are unified
  (`MfaEvidencePolicy`), the six places that *set* `amr` are not
- [ ] End-to-end tests proving a real MFA login satisfies Management and SCIM
  policies, and that a stale session cannot mutate credentials

`ReauthenticationController` and `IAuthenticationContextProjector` already
provide the ceremony and the projection into codes and tokens.

**Decided 2026-09-20 (owner).** A remembered-MFA device satisfies Management —
an operator does not repeat the second factor to read a page — but it does not
mint credentials. Delivered:
[`202609200800-remembered-second-factor.md`](../activities/202609200800-remembered-second-factor.md).
A remembered device no longer mints tokens for relying parties either: the
ceremony runs at the authorization endpoint, before the token exists
(2026-09-20, owner's call, globally) —
[`202609201100-authorize-step-up.md`](../activities/202609201100-authorize-step-up.md).

- [ ] Honour `acr_values`, ignored today, so a relying party that asks for an
  assurance level gets it rather than being silently given whatever the
  session has

## B. Token issuance and claim release

### B1 — One issuance kernel

PAT, CIBA and the OpenIddict grants still mint tokens through parallel paths,
so every policy decision can drift between them.

- [ ] Introduce `ITokenIssuanceService` and an issuance request/result contract
  shared by the OpenIddict grants, personal tokens and CIBA
- [ ] Centralize subject rehydration, claim destinations, scope/resource/
  audience attenuation, lifetime, token format, sender constraint, persistence,
  revocation, audit and metrics
- [ ] Extract the remaining grant handlers behind it, leaving the current
  routes as adapters
- [ ] Move CIBA token creation into the kernel and the standard
  token-processing boundary while keeping atomic one-shot consumption
- [ ] Characterize every current token shape and migrate one grant at a time,
  comparing claims and token metadata before removing each legacy branch

`ITokenGrantHandler` ×5 with `TokenGrantDispatcher`,
`IPrivilegedTokenMintingService` for personal/provisioning/operator tokens, and
`ITokenIssuancePolicyKernel` for scope attenuation are the pieces that already
exist. The kernel attenuates scopes and nothing else — it is not the issuance
service, and naming them alike would hide how much is still uncentralized.

**Done when:** no grant has a parallel issuance path and every scope, resource
and lifetime decision comes from one tested policy kernel.

### B2 — Claim release fails closed

- [ ] Add `IClaimReleasePolicy` considering client, grant, scopes, resources
  and destination
- [ ] **(operational)** Inventory every custom claim emitted in production and
  assign each a required scope, token destination, sensitivity and owning
  component
- [ ] Migrate the remaining claim mappings, then set
  `IncludeUnmappedClaimsInAccessTokens=false` with a strict allow-list

Sensitive unmapped-claim suppression already emits PII-free decision telemetry;
the inventory and the default flip are what remain.

### B3 — Token exchange provenance and delegation

- [ ] **(operational)** Characterize legacy tokens in Observe mode and migrate
  issuers and claims before enforcement
- [ ] Tests for a subject token from a foreign issuer, a personal token, a CIBA
  token, and sender binding carried across the exchange

Delegation depth is bounded since 2026-09-20
(`TokenExchange:MaxDelegationDepth`, default 5) —
[`202609200500-delegation-depth.md`](../activities/202609200500-delegation-depth.md).

Already in place, verified 2026-09-20: the actor allow-list
(`AllowedClientIds`), `may_act`, refusal of an actor token issued to another
client, confused-deputy refusal, and nested `act` chains — all tested.
Provenance has been **unconditional** since `1d04868` (2026-08-30, F-1):
evaluated on every exchange, with or without an allow-list; `Observe` remains
only as a migration valve, reported by the posture check and cleared by D4.
Missing and ambiguous `azp` are tested.

### B5 — CIBA trust boundary completion

- [ ] **(operational)** Inventory current CIBA callers in Observe mode,
  provision the missing entitlements, then enforce per client
- [ ] Run CIBA interoperability/conformance and approval-fatigue abuse tests
  before enabling additional clients
- [ ] Tests for a public or unauthenticated initiator and for rolling-deploy
  compatibility of the pending-request store. Missing entitlement, a
  mismatched polling client, one-shot consumption, concurrent consume with one
  winner, both client-authentication methods and disabled-404 are covered in
  `CibaTests`

`ICibaClientPolicy` and the bound, displayed `binding_message` are in place,
and `CibaProtocolFeature` already composes the whole capability as one unit:
disabled answers 404 (`CibaController.cs:75`), the grant handler refuses, and
the runtime capability is not advertised.

### B7 — Consent configuration fails closed

- [ ] **(operational)** Backfill null/unknown consent values to the intended
  legacy mode before enforcing validation

`AuthorizationConsentPolicy` already maps missing or unrecognized legacy
metadata to interactive consent at runtime; the data cleanup is what is left.

### B8 — Per-client OAuth resource validation

- [ ] **(operational)** Run the resource policy in Observe mode and provision
  explicit resource permissions for the existing MCP clients before enforcing

### B9 — FAPI 2.0: the one accepted conformance failure **(deferred by decision)**

`par-attempt-to-use-expired-request_uri` expects the error to reach the client
as a redirect carrying `invalid_request_uri`; the server refuses the expired
`request_uri` on its own error page. OpenIddict drops the request while
extracting it, before any redirect URI has been resolved — the request carries
only `client_id` and `request_uri` — so there is nowhere to send the error.

Attempted 2026-09-18 and reverted. A handler on
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

- [ ] **(operational)** Enable the vault in production and prove zero `pt1.`
  values and zero `pt1.` reads, a restorable backup, and a rollback that
  records no sensitive material
- [ ] Add an authorized rotation orchestrator with a distributed lock, progress
  journal, rewrap/re-encrypt strategy, rollback window and audit events
- [ ] **(operational)** Separate database-reader authority from KEK authority
  in production
- [ ] Tests: loss/recovery, old-version decrypt, concurrent rotate/encrypt,
  disaster restore

The vault module itself (phases 1–3: envelope crypto, named secrets, signing
keys) is delivered; `KeySource=certificate` with a dedicated KEK is deployed on
the three nodes. Procedure lives in `../runbooks/RUNBOOK-VAULT.md`.

### C2 — Signing and encryption key separation **(blocked)**

The three servers still use the same `certificate.pfx` for signing and
encryption. The runtime rejects every replacement PFX generated so far —
neither OpenSSL nor the .NET SDK produces one .NET 10.0.10 on those hosts will
load. Investigation:
[`202608161930-pfx-encryption-cert-investigation.md`](../activities/202608161930-pfx-encryption-cert-investigation.md).
`certificate-encryption.pfx` (RSA-3072, 10 years) is already staged on all
three. Recommended path: generate the certificate **on the server**, through a
CLI command of `Server.dll` itself.

- [ ] Generate the dedicated encryption certificate on the server, swap
  `EncryptionPath` in a window with token rotation, set
  `RequirePurposeSeparation=true`
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

### C3 — Authenticator and recovery material at rest

The standard ASP.NET Core Identity token store persists authenticator and
recovery-code material in `usertokens` with no application encryption adapter.

- [ ] Introduce an `IUserAuthenticationSecretStore` boundary backed by envelope
  encryption, with user ID, login provider and token name as AAD
- [ ] Implement dual-read: decrypt versioned ciphertext, accept legacy
  plaintext, rewrite legacy values on a successful read or mutation
- [ ] Add a background migration with checkpoints and redacted progress
  metrics — do not reset or disable anybody's existing MFA
- [ ] Coordinate secret rotation with security-stamp, session and token
  revocation and recovery-code regeneration
- [ ] Enable fail-closed encrypted writes first; disable plaintext reads only
  after migration telemetry reaches zero

### C4 — Verified transport everywhere

- [ ] **(operational)** Turn on verified TLS for RabbitMQ (`UseTls`, then
  `RequireTls`) and SMTP (`RequireTls`) in production. The gates, the TLS
  server name and certificate-revocation checking are already in the code
  (`RabbitMqEmailOptions`, `DefaultEmailSenders`), and plaintext logs a
  warning at startup
- [ ] **(operational)** Select `RequireVerifiedTls` — or the audited
  `PrivateSocket` exception — in each production deployment, after the CA or
  socket is provisioned

An explicit transport policy already validates VerifyCA/VerifyFull or a
UnixSocket exception; production still has to choose the mode.

### C5 — Legacy credential inventory and rotation **(operational)**

- [ ] Inventory and rotate the legacy database and provider credentials and
  certificates, migrate `deploy/local/` to the approved secret store, and
  attach a redacted manifest with owner, version, state and retirement date

---

## D. Production posture and configuration

### D1 — CSP from telemetry to enforcement

- [ ] **(operational)** Inventory the actual image, style and script origins
  against the rendered UI
- [ ] Extract the inline `style="…"` attributes from the management pages.
  A per-request nonce for `<style>` elements already exists (`Csp:UseNonce`,
  opt-in), but a nonce cannot authorize an attribute, and Firefox has no
  `style-src-attr` — so the nonce stays off until the attributes are gone
- [ ] Exercise every public and management flow in report-only mode, triage the
  violations, then enforce by deployment cohort — `ReportOnly=false`
- [ ] Keep a bounded report-only rollback switch and record no sensitive URL or
  query data in the reports

Procedure: [`RUNBOOK-CSP-CALIBRATION.md`](../runbooks/RUNBOOK-CSP-CALIBRATION.md).
The placeholder external image host and the websocket wildcards were already
removed from the three servers.

### D2 — Public origin enforcement

- [ ] **(operational)** Inventory the proxy paths and public hosts, eliminate
  request-derived security URLs, and switch `PublicOrigin.Mode` to `Enforce`

### D3 — Explicit deployment topology

- [ ] **(operational)** Inventory the current production topology, configure it
  explicitly, then make `FailOnUntrustedProxy`/`RequireShared` derived
  fail-closed requirements
- [ ] Add a two-replica DPoP/CIBA/passkey smoke test

### D4 — Enforcement-mode inventory per environment **(operational)**

- [ ] For each environment, inventory SCIM, token exchange, personal tokens,
  CIBA, credential mutations, public origin and Management; remove every
  `Observe`/`Audit`/authorization-off setting, or register a valid temporary
  exception with owner and expiry

The posture check already reports `ciba-client-policy-observe`,
`personal-tokens-observe`, `token-exchange-provenance-observe` and
`credential-mutations-step-up-audit` — this item is the pass that empties them.

### D5 — Real shared cache

- [ ] **(operational)** Configure the real Redis `IDistributedCache` in every
  environment and pass the issuance/consumption/replay rehearsal across
  multiple replicas

`AddStackExchangeRedisCache` is wired and `HostStartupGuards` refuses to scale
out without it; the multi-replica rehearsal is the missing evidence.

### D6 — Distributed abuse protection

Lockout is 5 failures in 5 minutes. The rate limiter is an in-process
`PartitionedRateLimiter` — each replica counts on its own — partitioned by path,
method and IP; there is no account dimension (verified 2026-09-20).

- [ ] Implement shared partitions by endpoint, client, HMAC-normalized account
  and IP, with progressive delay and bounded lockout behaviour; use exponential
  backoff or a window of at least 15 minutes
- [ ] Add `HumanVerificationFlow.Login` CAPTCHA after N failures per account/IP
- [ ] Add dummy password work and response/timing normalization wherever user
  existence can be inferred
- [ ] Validate the trusted-proxy configuration at startup and integrate
  edge/WAF signals without treating them as the only control
- [ ] **(operational)** Tune with production shadow metrics, including NAT
  false-positive and botnet-spray scenarios

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

### E1 — Client operational state (enable/disable)

`OpenIddictEntityFrameworkCoreApplication` has no enablement field. The list can
honestly report only `active`, because that is the only state the runtime
enforces. Showing `blocked`, `disabled` or `revoked` before the endpoints
consult and apply the decision would be a false indication to the operator.

**Model.** A dedicated operational-state table keyed by the OpenIddict
`ApplicationId`, rather than overloading `applications.properties`:
`application_id` (unique, logical FK to `applications.id`), `status`
(`active` | `disabled` in this first version), optional `reason` carrying no
secret, plus `changed_at_utc`, `changed_by_subject` and `version` for audit and
optimistic concurrency. **The absence of a row means `active`**, which keeps
every existing client working. `revoked` is deliberately not an application
state: tokens, authorizations and sessions have their own lifecycle and are
already revoked by the existing OpenIddict services.

- [ ] Additive migration and index on `application_id,status`
- [ ] Enforcement — required *before* any new filter appears in the UI or the
  API — at: `connect/authorize` and consent; `connect/token`, including refresh
  token and client credentials; PAR and device authorization/token;
  introspection, userinfo and any endpoint accepting a `client_id` to start a
  protocol operation; Management API create/edit/remove with audit and its own
  capability
- [ ] The verifier returns a consistent OAuth error (`invalid_client` or
  `unauthorized_client` per protocol point), logs client ID and state without
  sensitive data, and keeps cache invalidation coherent with the OpenIddict
  application cache
- [ ] Optional backfill for explicitly known states only; absence stays `active`
- [ ] Start with read/telemetry, blocking no traffic; enable blocking by
  capability/configuration after authorize, token, PAR and device are tested on
  representative clients
- [ ] Allow manual change only for clients not managed by a manifest
- [ ] Audit, optimistic concurrency and a documented rollback
- [ ] UI last: expose only `Todos`, `Ativos` and `Desabilitados`, with origin,
  reason and date of the last change; show the impact before confirmation and
  keep the filter in the URL. No "revoked" in the filter

**Done when:** authorize, token, PAR and device consistently refuse a disabled
application; reactivation restores the flow without erasing historical tokens
or authorizations; API, UI, audit and metrics show the same state; and
contract, integration, concurrency, cache and rollback tests pass.

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

- [ ] Disable/enable action wired to E1's enforcement
- [ ] Per-application metrics connected to the existing metrics module
- [ ] Audit timeline filtered by client ID
- [ ] Session and authorization revocation actions in the application's context
- [ ] Volume test with thousands of clients

### E4 — Application advanced settings (only where enforcement is real)

- [ ] Typed public metadata (`description`, `client_uri`, `logo_uri`)
- [ ] Application claims with allow-list and destinations
- [ ] Advanced properties with a namespace and reserved keys
- [ ] Per-client DPoP/JAR/CIBA/FAPI configuration only where the runtime
  actually honours it
- [ ] New profiles only when each has a validator, an explanation and tests

Per-application access, identity and refresh token lifetimes already exist on
create and update (`ClientTokenLifetimePolicy`), as does per-client PAR.

### E5 — One result-state component for the Management console

`ManagementDataResult<T>` models `Success`, `Forbidden`, `StepUpRequired`,
`Unavailable`, `NotFound` and `Invalid` — a rich contract, consumed unevenly.
Coverage improved over the last month, but every page still writes the
conditional tree by hand, so the cheap path is still to handle the happy case
only. Of the 24 pages consuming the contract (2026-09-19): `StepUpRequired` 14,
`Invalid` 12, `Forbidden` 11, `NotFound` 11, `Unavailable` 10. On the rest, an
operator without permission and a backend that is down look identical.

- [ ] Create `ManagementDataView<T>` in `Sufficit.Identity.UI.Components`: takes
  a `ManagementDataResult<T>`, renders the matching state, with a
  `RenderFragment` for success and standard messages for the others. It must
  compose with `EmptyState`, not replace it
- [ ] Define the canonical message per outcome — text, tone and suggested
  recovery action — so the same condition presents identically everywhere
- [ ] Announce state transitions accessibly (`aria-live`) inside the component,
  so pages inherit the behaviour instead of repeating it
- [ ] Migrate first the pages handling neither `Forbidden` nor `Unavailable`
- [ ] Migrate the rest, deleting the duplicated conditionals
- [ ] Tests: each outcome renders its state; success with an empty collection
  stays distinguishable from failure
- [ ] Re-measure the largest pages (`Branding.razor`, `UserDetail.razor`,
  `Clients.razor`) afterwards to see how much of their length was duplication

Out of scope here: visual redesign, information hierarchy, and any change to
`ManagementDataResult<T>` itself, which is adequate.

### E6 — Mobile-first validation and rollout

- [ ] Deliver and test the client configurator at 320–430 px first, then tablet
  and desktop
- [ ] Automated visual inspection at 320, 360, 390 and 430 px
- [ ] Validate keyboard, focus, virtual keyboard, deep link, F5 and concurrency
  on the creation and edit flows
- [ ] **(operational)** Publish the update capability per deployment and
  validate the real clients

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
- [ ] Extract the runtime copy — it is currently hardcoded pt-BR

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

- [ ] Replace the `DemandAsync`/`TryWriteAuditAsync` pair repeated across six
  services with a `ManagementOperationExecutor`
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

### F8 — Fresh-install and additive SQL parity

- [ ] Compare the resulting legacy-schema state against the canonical
  fresh-install schema for every additive script through HEAD

### F9 — Unambiguous normalized email identity

- [ ] **(operational)** Run the redacted duplicate report from script 083 and
  clean up, preserving existing accounts
- [ ] Add registration, SCIM update, email change, login and recovery race tests

Recovery, external-login, CIBA and passkey lookups already reject ambiguous
normalized matches, and 083 provides the guarded nullable unique index.

### F10 — Dynamic client registration lifecycle

- [ ] Implement protected read, update, delete, secret rotation and the audit
  lifecycle
- [ ] Apply one canonical metadata validator, including strict URI schemes and
  loopback redirect rules
- [ ] Retain caller-supplied secrets only behind a deprecated audited adapter
  during migration, with an entropy floor and a deadline
- [ ] Align the operator-managed application lifecycle and secret references
  with E2
- [ ] Keep DCR disabled until the lifecycle, abuse controls and interoperability
  tests are complete

Server-generated IDs and secrets, expiring single-use initial access tokens,
central metadata validation and public-client PKCE are already covered.

### F11 — Breached-password availability policy

- [ ] Add the third mode. `BreachedPasswordFailureMode` exists with `FailOpen`
  (the compatibility default) and `FailClosed`; `LocalFallback` is what is
  missing, and `fail-open` already has a posture finding
- [ ] Add a bounded local compromised-password fallback and cache successful
  HIBP range responses — `BreachedPasswordValidator` caches nothing today
- [ ] Timeout, upstream-error, malformed-response and recovery tests, plus
  degraded-mode metrics
- [ ] **(operational)** Move regulated environments to `LocalFallback` or `Deny`
  only after audit telemetry characterizes latency and availability

### F12 — GCM budget

- [ ] Auto-rotate the DEK at its budget, or drive rotation from a durable
  counter. `VaultCryptographyTelemetry` warns at 80% and logs critical at 100%,
  but it counts **per process** in a `ConcurrentDictionary`, so three replicas
  reach the real budget while each reports a third of it. Automatic rotation is
  disabled on purpose until the aggregated metric exists

### F13 — Split operational and security contexts

- [ ] Split the operational/security `DbContext`s and their migrations — only
  after transactional boundaries and outbox behaviour are defined. Splitting the
  current `DbContext` was evaluated and **withdrawn**: `OnModelCreating` is 17
  cohesive methods, none over 137 lines, and the cost lands on hand-sequenced
  production SQL across a multimaster cluster

### F14 — Security-critical protocol annotations

- [ ] Remove comments claiming a guard is unconditional where composition makes
  it conditional
- [ ] Review security comments against executable tests and delete the
  historical "item fixed" narratives that no longer describe current behaviour

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

OIDC Basic (36 modules) and the FAPI 2.0 Security Profile (56 modules) run
green nightly since 2026-09-18 —
[`202609171900-openid-conformance-gate.md`](../activities/202609171900-openid-conformance-gate.md).

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

Database and provider gates are complete
([`202608011820-legacy-cutover-db-provider.md`](../activities/202608011820-legacy-cutover-db-provider.md)).
Everything below needs a human against real infrastructure and clients.

**Clients**

- [ ] Every active client has an assigned owner and a documented final state
- [ ] Implicit/hybrid/password consumers migrated to authorization_code + PKCE,
  or retired
- [ ] Confidential clients have newly issued, post-migration credentials
- [ ] PKCE S256 enforced on every authorization-code client
- [ ] Redirect, logout and CORS allow-lists verified per client
- [ ] Token format validated by every resource server (reference vs JWT)

**Keys and infrastructure**

- [ ] Signing/encryption key distribution tested end to end (PFX on every
  replica)
- [ ] JWKS overlap and rotation tested — old and new keys visible during the
  transition
- [ ] Proxy and forwarded headers verified end to end
  (`X-Forwarded-Proto`/`Host`, TrustedProxies)
- [ ] Management parity verified, or temporary legacy administration approved

**Rehearsals**

- [ ] Backup, cutover and rollback rehearsals complete and recorded
- [ ] No migration step depends on a secret in source control (gitleaks clean)

### G5 — Confirmed-email rollout **(operational)**

- [ ] Execute [`RUNBOOK-CONFIRMED-EMAIL.md`](../runbooks/RUNBOOK-CONFIRMED-EMAIL.md)
  — rollout and migration of the legacy users

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

1. **Done.** A5, A6 and D1 were delivered on 2026-09-19:
   [`202609191500-enumeration-legacy-grants-revoker.md`](../activities/202609191500-enumeration-legacy-grants-revoker.md),
   [`202609191700-passkey-assurance.md`](../activities/202609191700-passkey-assurance.md)
   and
   [`202609191900-posture-check-coverage.md`](../activities/202609191900-posture-check-coverage.md).
   Three of D1's new findings are advisories that every deployment sees until
   it settles them — `access-token-unmapped-claims` is B2's work,
   `certificate-purpose-not-separated` is C2's, and
   `token-exchange-enabled-by-default` clears when D4 declares the switch. They
   are the plan made visible at startup.
2. **C1, then C2** — the vault's production enablement, then the key
   separation. C2 is blocked on the PFX problem and needs the
   generate-on-server approach first. C1 (the plaintext boundary) was
   delivered on 2026-09-19, see
   [`202609192100-secret-boundary-provenance.md`](../activities/202609192100-secret-boundary-provenance.md);
   declaring `Sufficit:Vault:SecretMigrationComplete=true` per environment is
   part of D4.
3. **A1** — what remains is operator entitlements. Protected principals
   across every capability that reaches a user was delivered on 2026-09-19.
4. **B1** — the issuance kernel, one grant at a time under characterization
   tests. B2, B3 and B5's kernel item depend on it; do not start them first.
5. **B7, B8** — independent of the kernel, both operational. B4 (DPoP nonce
   isolation) and B6 (JAR and JARM) were delivered on 2026-09-19/20, see
   [`202609200100-dpop-stateless-nonce.md`](../activities/202609200100-dpop-stateless-nonce.md)
   and
   [`202609200300-jar-jarm-already-built.md`](../activities/202609200300-jar-jarm-already-built.md).
6. **D4, D2, D3, D5** — the enforcement and topology inventories, together, per
   environment. They are what actually turns Observe into Enforce, and they
   are what clears the advisories the posture check now reports at every
   startup.
7. **E1** — enforcement first, UI last. E3's disable action waits on it.
8. **E5, E6** — console consistency and the mobile pass; independent of the
   protocol work and safe to run in parallel with it.
9. **E2, E4, E7, F1–F14** — as capacity allows, in the order the team prefers;
   none of them blocks another.
10. **G** — conformance, audit, cutover and rehearsals, continuously, and G4
    before anyone calls the legacy migration finished.

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

## Where the retired plans went

| Retired plan | Now |
|---|---|
| `PLAN-GPT-5-REMAINING` | A1, A4, B1–B3, B5, C2, C4, D2, D6, F3, F4, F5, F10, F13, G1, G2, G3 |
| `PLAN-GLM-5-2-REMAINING` | A1, A2, A3, B1, F3, F6, F11 |
| `PLAN-SECURITY-HARDENING-WAVE-2` | A1, A2, A3, B2, B3, B5, B7, B8, C2, C3, C4, D1, D3, F6–F10, F14, closure criteria |
| `PLAN-FABLE-5-TRIAGE` | A4, B2, B3, C2, D6, F2, F12 |
| `PLAN-PRODUCTION-READINESS` | C1, C2, C5, D1, D4, D5, E8, F3, G2, G5, G6 |
| `PLAN-MANAGEMENT-APPLICATIONS` (+ `-NEXT`) | A2, E1–E4, E6 |
| `PLAN-CLIENT-OPERATIONAL-STATE` | E1 |
| `PLAN-MANAGEMENT-UI-STATE-CONSISTENCY` | E5 |
| `PLAN-PLUGGABLE-UI-PHASES-2-5` | E7 |
| `PLAN-LEGACY-CUTOVER-OPS` | G4 |
| `PLAN-FAPI2-CONFORMANCE` | B9 |
| `PLAN-VAULT`, `PLAN-VAULT-UI`, `PLAN-STRIX-IDENTITY`, `PLAN-SHARED-FRONTEND-STRATEGY`, `PLAN-20260814-EVEO-APPS-HEALTHCHECK` | delivered; retired 2026-09-19 |

The delivered work behind every one of them is in `../activities/`. The vault's
operational procedure is `../runbooks/RUNBOOK-VAULT.md`; the conformance
environment and its accepted results are `conformance/README.md` and
`conformance/config/`.
