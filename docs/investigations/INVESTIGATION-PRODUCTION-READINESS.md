# Production-readiness investigation

Date: 2026-08-02

Decision: **NO-GO for issuer cutover**

## Scope

This investigation consolidates repository tests, a read-only inventory of the
legacy issuer and repeated migration rehearsals against a disposable restore of
a real logical backup. It intentionally records no credentials, internal
topology, production client identifiers, user data or raw traffic counts.

It evaluates readiness to replace the legacy protocol runtime. It does not
start the planned future removal of OpenIddict, and it does not make the UI or
Management modules responsible for protocol persistence.

## Evidence that is green

- The fixed MariaDB/EF provider package and symbols have approved SHA-256
  checksums enforced before CI restore.
- The canonical empty-database schema, additive legacy schema and isolated
  migration history have automated contracts.
- Three fresh restores of a real backup passed the guarded database-only
  rehearsal. Shared Identity structures and counts were unchanged, refresh
  state was unchanged and eligible legacy API-token identifiers became
  revoked, payload-free tombstones.
- The disposable dump, logs and rehearsal schemas were destroyed after the
  rehearsal, and the source database was verified unchanged.
- `SufficitWebForms` and `SufficitEndPointsSwaggerUI` have verified modern
  replacements using authorization code and PKCE S256.
- OIDC front-channel and back-channel logout are implemented through
  provider-neutral services. The runtime issues a stable `sid` per login,
  advertises session support, validates registered logout URIs and delivers
  standards-shaped logout notifications.
- Controlled reauthentication is approved. Non-portable sessions and grants
  are not converted; users sign in again after cutover.

## Blocking findings

The read-only live inventory still contains active clients in one or more of
these categories:

- implicit, hybrid or password grants;
- authorization-code consumers without required PKCE S256;
- confidential clients whose legacy hashes cannot supply a new plaintext
  credential;
- redirect, post-logout, front-channel logout or CORS allowlists that have not
  yet been reconciled with a reviewed manifest.

The following operational gates also remain open:

- every active client has an owner and an explicit migrate/retire/rollback-only
  decision;
- all confidential replacements have credentials newly issued through the
  approved secret store;
- each resource server validates the selected token format, issuer, audience,
  algorithms and key rotation;
- production signing and encryption keys are distributed and tested across
  issuer nodes, including JWKS overlap and emergency rotation;
- trusted proxies, forwarded headers, HTTPS issuer construction and client IP
  propagation are verified end to end;
- Management parity or a bounded legacy-administration fallback is approved;
- a full blue/green cutover and rollback rehearsal exercises login, consent,
  token, refresh, UserInfo, API validation and both logout modes;
- the credential formerly embedded in the deleted historical migration helper
  is rotated and the candidate history passes secret scanning.

## Required sequence before production

1. Export a sanitized active-client worksheet from the live inventory and
   assign an owner and final state to every entry.
2. Complete the secret-free provisioning manifest and resolve every obsolete
   flow, PKCE gap and URI/CORS allowlist difference.
3. Issue new confidential-client credentials outside source control and apply
   the manifest first to a disposable rehearsal environment.
4. Install production signing/encryption material, validate token compatibility
   in every API and prove JWKS rotation.
5. Validate the real proxy path and run the complete synthetic protocol suite
   off-path against the green deployment.
6. Rehearse traffic switch, rollback and reconciliation from a fresh backup.
7. Rotate the historical migration credential, scan the complete candidate and
   close every checkbox in `PLAN-LEGACY-CUTOVER.md`.
8. Schedule the cutover only after an explicit go/no-go review.

## Production rule

Code may be merged and deployed to a non-serving green environment while this
decision is NO-GO. Public issuer traffic, production schema and client
credentials must not be changed until every required migration gate is closed.
