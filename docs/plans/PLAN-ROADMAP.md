# Sufficit Identity roadmap

Status: **active**
Last consolidated: **2026-08-01**

This is the only active product roadmap in the repository. Completed session
plans and dated evaluations are historical evidence, not parallel backlogs.

## Completed baseline

- The runtime, public/account UI and Management UI are separate .NET projects
  in one repository, one process and one deployment artifact.
- Both UIs use canonical application contracts and have no direct dependency on
  Identity stores, EF Core or OpenIddict managers.
- OAuth/OIDC, Management, SCIM, account-management and provisioning surfaces
  have integrated architecture, routing and protocol tests.
- The Release pipeline builds with warnings as errors, applies the canonical
  schema to MariaDB, executes 229 tests, scans secrets and audits dependencies.
- Commit `c0218c07a7bdc904bd85b08c55d106142ba14b69` is deployed and healthy in
  the `castrum-apps` test environment.

## Active work

### 1. Legacy cutover

Status: **not started operationally**

The migration implementation and rehearsal assets exist, but production
cutover is controlled separately. Before replacing the legacy service:

- rehearse against a disposable copy of a real backup;
- assign an owner and final state to every active client;
- migrate or retire legacy grants and rotate confidential-client credentials;
- validate redirect, logout, CORS, token-format and resource-server behavior;
- test signing/encryption key distribution and JWKS overlap;
- execute and record backup, cutover and rollback rehearsals.

The authoritative gate list is
[PLAN-LEGACY-CUTOVER.md](PLAN-LEGACY-CUTOVER.md).

### 2. Production security policy

Status: **partially complete**

- Calibrate the emitted CSP in report-only mode, then explicitly decide when to
  enforce it in each production environment.
- Execute
  [RUNBOOK-CONFIRMED-EMAIL.md](../runbooks/RUNBOOK-CONFIRMED-EMAIL.md) before
  relying on confirmed e-mail for migrated accounts and external providers.
- Replace unencrypted database persistence of Data Protection key material with
  an approved at-rest protection mechanism before the threat model requires it.
- Introduce a shared distributed cache/store before running multiple replicas
  for passkey temporary tickets, DPoP replay/nonce state or CIBA pending state.

### 3. Protocol interoperability

Status: **incremental, demand-driven**

- Complete and test remaining front-channel logout interoperability. Keep
  unsupported behavior unadvertised until it is real.
- Use a durable dispatcher for back-channel logout before deployments require
  reliable fan-out across process restarts.
- Keep CIBA disabled unless a concrete integration justifies completing its
  durable state, reference-token, introspection and revocation behavior.
- Treat FAPI profiles, RAR, federation and other optional extensions as
  independent capabilities with conformance evidence, not checkbox features.
- A future replacement of OpenIddict remains planned architecture, not active
  implementation. New work continues through neutral application contracts.

### 4. SCIM interoperability

Status: **core subset implemented**

Users, Groups, filtering and PATCH are available. Bulk, sorting and ETags stay
unadvertised. Add them only for a concrete provisioning integration and test
that integration against the relevant RFC behavior.

### 5. Product quality

Status: **continuous**

- Complete a recorded WCAG 2.2 AA keyboard, focus, contrast and screen-reader
  audit for both embedded UIs.
- Add localization only after extracting runtime copy without creating a second
  source of protocol or business truth.
- Re-run the independent evaluation prompt after a material protocol or
  production-readiness milestone; move surviving findings into this roadmap.

### 6. Pluggable and remote user interfaces

Status: **foundation in progress**

- Make the identity runtime executable without either UI surface.
- Preserve the current embedded deployment as the compatible default.
- Extract UI-facing application contracts into implementation-neutral packages.
- Add an optional BFF deployment for the Management UI before attempting a
  remote public authentication surface.
- Specify and threat-model an opaque interaction protocol before allowing the
  public/account UI to run outside the runtime process.

The phases and acceptance gates are maintained in
[PLAN-PLUGGABLE-USER-INTERFACES.md](PLAN-PLUGGABLE-USER-INTERFACES.md).

## Explicit non-goals for the current phase

- Do not replace OpenIddict merely to prove replaceability.
- Do not move Sufficit business roles, directives, tenants or reseller rules
  into the generic identity provider.
- Do not force the current embedded UIs into separate deployments. Remote UI
  hosts are optional adapters and the compatible embedded mode remains supported.
- Do not implement an optional RFC extension without an integration or threat
  model that defines its acceptance criteria.

## Completion rule

An item leaves this roadmap only after code, tests and any required operational
evidence are complete. A feature that is disabled, unadvertised or awaiting a
production decision remains visible with that exact status.
