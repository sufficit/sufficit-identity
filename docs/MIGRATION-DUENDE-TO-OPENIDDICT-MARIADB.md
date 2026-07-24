# Migrating Duende IdentityServer to OpenIddict on MariaDB

## Purpose

This document is a reusable migration guide for applications that:

- use ASP.NET Core Identity for users, roles, claims and external logins;
- use Duende IdentityServer, often through a Skoruba-based host;
- want to move the OAuth 2.0/OpenID Connect server to OpenIddict;
- must keep the existing MariaDB database as the system of record;
- cannot accept avoidable downtime or silent client breakage.

It intentionally contains no organization-specific hostnames, client IDs,
traffic counts, credentials, user data or infrastructure topology. Replace
every `example_*` value with an environment-specific value outside source
control.

This is a living document. Update the decision log, implementation log and
gates whenever a migration step changes.

## Executive summary

Duende and OpenIddict implement the same protocol families, but their
persistence models, token formats, key management and compatibility defaults
are not interchangeable.

The safest database strategy is usually:

1. keep the existing ASP.NET Core Identity tables as the single source of
   truth;
2. keep the Duende operational tables available during transition;
3. add the OpenIddict protocol tables alongside them;
4. use a separate EF migration-history table for the new model;
5. migrate client configuration through a versioned manifest;
6. do not copy Duende grants or secret hashes as if they were OpenIddict
   credentials;
7. modernize active clients before changing the issuer implementation;
8. cut over the issuer as one controlled unit, with an explicit rollback
   policy.

This strategy changes the schema additively. It does not require moving data
to MySQL, creating a second production identity database or synchronizing two
copies of the user store.

## Target composition

A maintainable solution separates hosting from protocol modules:

| Component | Responsibility |
|---|---|
| Server | Executable host, configuration, middleware, health, logging and lifecycle |
| STS | Identity and OAuth/OIDC endpoints |
| Management | Administrative API |
| Core | Shared entities, contracts, persistence and migrations |
| UI | Login, consent, device flow, recovery and account pages |

Only the Server should be a composition root. Module projects should not own
Kestrel configuration, environment appsettings or deployment lifecycle.

## What is portable

### Reuse in place

When the EF mapping is identical, these ASP.NET Core Identity assets can remain
in the existing database:

- users;
- roles;
- user and role claims;
- external logins;
- user-role mappings;
- user tokens;
- passkeys;
- ASP.NET Core Data Protection keys.

Reusing tables is safer than copying them because there is no replication lag
or last-minute delta to reconcile.

### Recreate from declarative configuration

Recreate these objects through an idempotent, versioned manifest:

- clients/applications;
- redirect and post-logout redirect URIs;
- allowed grants and response types;
- scopes and resources;
- CORS origins;
- PKCE requirements;
- token format and lifetime policy;
- display names and deprecation metadata.

Client secrets must be newly issued through the approved secret store.
A Duende secret hash is not the original secret and cannot be reused as an
OpenIddict secret.

### Do not convert row by row

The following state is implementation-specific and commonly protected with
different formats or keys:

- authorization codes;
- refresh tokens;
- reference tokens;
- device codes;
- user consents;
- pushed authorization requests;
- server-side sessions;
- browser authentication cookies.

Choose one of these policies:

1. keep a temporary validation/introspection bridge until old tokens expire;
2. coordinate controlled reauthentication and make every client handle
   `invalid_grant` safely.

Database equivalence alone does not preserve these artifacts.

## Database layout

### Shared tables

Map every shared table explicitly. Do not rely on provider conventions for
names, lengths, indexes or generated defaults.

At minimum, validate:

- table and column names;
- nullable flags;
- varchar and varbinary lengths;
- primary and foreign keys;
- unique and composite indexes;
- timestamp precision and defaults;
- passkey representation;
- Data Protection column names.

Any difference must fail rehearsal rather than being corrected silently.

### OpenIddict tables

The additive path creates:

- `applications`;
- `authorizations`;
- `scopes`;
- `tokens`;
- a dedicated migration-history table.

In this repository the dedicated history table is:

```text
__sufficit_identity_migrations
```

It must not reuse the legacy Duende/Skoruba history table.

### Why additive DDL needs rehearsal

MariaDB DDL performs implicit commits. Wrapping `CREATE TABLE` in
`START TRANSACTION` does not make a multi-table schema change atomic.

The operational safeguards are therefore:

- a tested backup;
- a disposable rehearsal restored from that backup;
- a read-only preflight;
- fail-fast DDL without `IF NOT EXISTS`;
- schema comparison before and after;
- a documented abort procedure.

`IF NOT EXISTS` is inappropriate for this migration because it can hide drift
under an object with the expected name but the wrong shape.

## MariaDB and EF provider compatibility

Database engine choice and EF provider choice are separate decisions.
Keeping MariaDB does not require moving to MySQL merely because a package name
contains `MySql`.

Before production use, freeze a combination where the provider explicitly
supports:

- the selected .NET/EF Core version;
- the selected MariaDB release;
- migration generation and execution;
- required data types and index lengths;
- database locking behavior.

The compatibility implementation in this repository exposed an important
failure mode: the Oracle EF Core migrator attempted to cast a MariaDB
`GET_LOCK()` `NULL` result to `Int64` before executing DDL. The CI therefore:

1. regenerates and compares the canonical SQL through a contract test;
2. applies that checked-in SQL with MariaDB's own client;
3. records the EF provider as an open runtime gate.

This validates the schema without pretending that an unsupported runtime
provider is production-ready.

Another provider-specific issue is idempotent migration generation that emits
`IF ... BEGIN` blocks not accepted by MariaDB. Prefer reviewed, explicit SQL
for the additive legacy path.

## Repository migration assets

| Asset | Purpose |
|---|---|
| `docs/migration/sql/001-create-empty-database.sql` | Build the canonical schema in an empty database |
| `docs/migration/sql/010-preflight-legacy.sql` | Read-only compatibility gate for a legacy clone |
| `docs/migration/sql/011-add-openiddict-to-legacy.sql` | Add only OpenIddict tables and isolated history |
| `docs/migration/fixtures/legacy-schema-mariadb-10.4.sql` | Schema-only disposable rehearsal fixture |
| `src/tests/DatabaseSchemaContractTests.cs` | Enforce model, SQL and additive-contract invariants |
| `src/tests/MariaDbMigrationIntegrationTests.cs` | Execute empty and legacy paths against MariaDB |

The fixture is structural test data. It contains no rows or credentials.
Because table definitions may be captured in alphabetical rather than
foreign-key dependency order, its reconstruction session temporarily disables
`FOREIGN_KEY_CHECKS` and re-enables them before preflight.

## Phase 0: inventory and decisions

### Record immutable facts

- Duende and Skoruba versions;
- .NET and EF Core versions;
- MariaDB version and topology;
- issuer and discovery endpoints;
- signing and encryption key ownership;
- Data Protection configuration;
- active grants and response types;
- active token formats;
- clients with refresh/reference tokens;
- browser clients and CORS origins;
- administrative features in use.

Store only aggregate counts and sanitized identifiers in public artifacts.
Keep raw logs, connection strings and credentials out of the repository.

### Decide before coding

- Will old tokens remain valid temporarily, or will users reauthenticate?
- Which provider/EF/MariaDB combination is supported?
- Which legacy clients will be modernized, deprecated or removed?
- Will legacy administration remain available during transition?
- What are the RPO, RTO and rollback thresholds?

Do not schedule a cutover while these decisions remain implicit.

## Phase 1: modernize clients

OpenIddict intentionally should not be configured to preserve obsolete flows
indefinitely.

Recommended final profiles:

| Client type | Recommended flow |
|---|---|
| Server-side web | Authorization Code + PKCE S256 + confidential authentication |
| Browser SPA | Authorization Code + PKCE S256, no browser-held secret |
| Native/mobile/desktop | Authorization Code + PKCE S256 with system browser |
| Service-to-service | Client Credentials with rotated secret or stronger client authentication |
| Input-constrained device | Device Authorization |
| Interactive API documentation | Authorization Code + PKCE S256 |

Retire or isolate:

- implicit;
- hybrid;
- Resource Owner Password Credentials;
- `plain` PKCE;
- custom grants without an explicit replacement contract.

For each client, test:

- authorization redirect;
- callback method and response mode;
- token exchange;
- refresh behavior;
- UserInfo claims;
- API audience validation;
- logout behavior;
- error handling without redirect loops.

### Example public client manifest

```json
{
  "client_id": "example_web",
  "display_name": "Example Web",
  "client_type": "confidential",
  "grant_types": ["authorization_code", "refresh_token"],
  "require_pkce": true,
  "pkce_methods": ["S256"],
  "redirect_uris": ["https://example.invalid/oauth/callback"],
  "post_logout_redirect_uris": ["https://example.invalid/"],
  "scopes": ["openid", "profile", "email", "example_api"],
  "secret_reference": "secret-store://identity/example_web"
}
```

The manifest stores a logical secret reference, never a secret value or
password-derived hash.

## Phase 2: create the schema baseline

1. Pin the EF migration tool.
2. Map the existing shared tables exactly.
3. Configure a dedicated migration-history table.
4. Generate a canonical empty-database migration.
5. Generate a reviewed empty-database SQL script.
6. Create a separate additive script for the legacy schema.
7. Add a read-only preflight that returns zero rows on success.
8. Fail when OpenIddict tables or the new history table already exist.

The additive script must not:

- alter shared Identity tables;
- copy user data;
- drop legacy tables;
- use a production connection string;
- contain secret values.

## Phase 3: automated rehearsal

The CI rehearsal should use the same MariaDB release family as the deployment
baseline, without requiring a database server on developer machines.

### Empty database path

1. Start an ephemeral MariaDB service.
2. Create an empty database.
3. Apply the canonical SQL.
4. Verify no pending migrations.
5. Verify the migration-history row.
6. Verify all expected tables, indexes and critical types.

### Legacy path

1. Create a fixed-name, loopback-only rehearsal database.
2. Load the schema-only legacy fixture.
3. Require a zero-row preflight.
4. Fingerprint shared columns, indexes and foreign keys.
5. Apply the additive script.
6. Fingerprint shared objects again and require exact equality.
7. Verify only the OpenIddict tables and new history were added.
8. Drop the rehearsal database in `finally`.

Destructive test code must require all of:

- CI mode;
- an explicit opt-in environment variable;
- a loopback host;
- an exact, fixed source database name;
- an exact, fixed rehearsal database name.

These guards prevent accidental execution against an arbitrary host.

## Phase 4: rehearsal with a real backup

Schema-only CI proves DDL compatibility, not data behavior.

Before any migration window:

1. restore a fresh encrypted backup into an isolated environment;
2. verify access is restricted and audited;
3. run the preflight;
4. run the additive script;
5. compare table structures;
6. compare aggregate counts and non-reversible checksums;
7. provision clients/scopes from the manifest;
8. execute end-to-end login, refresh, UserInfo, API and logout tests;
9. destroy the rehearsal environment according to retention policy;
10. repeat from a fresh backup to prove determinism.

Never publish the backup, SQL row dumps, password hashes, personal claims or
raw tokens as CI artifacts.

## Phase 5: keys and token compatibility

### Signing and encryption

OpenIddict needs stable signing and encryption credentials shared by all
issuer nodes.

The runbook must define:

- source of key material;
- file/store permissions;
- key identifiers;
- public JWKS overlap period;
- rotation schedule;
- emergency revocation;
- startup behavior when keys are unavailable.

Development certificates are not production credentials.

### Access-token format

Do not assume disabling reference tokens automatically produces the same JWT
format as Duende. Validate whether APIs expect:

- signed JWS;
- encrypted JWE;
- reference tokens with introspection.

Test issuer, audience, algorithm, claims, clock skew and key rotation in every
resource server.

### Cookies and Data Protection

Sharing a Data Protection key ring does not by itself prove cookie
compatibility. Cookie name, domain, path, scheme, serializer, purpose strings
and application name must also match.

If compatibility is not demonstrated, plan controlled reauthentication.

## Phase 6: proxy, CORS and operational readiness

Validate the full public path:

```text
DNS -> load balancer -> TLS proxy -> ASP.NET Core host
```

Check:

- trusted forwarded-header proxies/networks;
- canonical HTTPS scheme and issuer;
- callback and logout URLs;
- per-client CORS allowlists;
- real client IP propagation;
- liveness and readiness separation;
- rate-limit partitioning;
- immutable artifact digest across nodes;
- structured logs without tokens, codes, cookies or PII.

Never combine credential rotation and issuer cutover in the same untested
change.

## Cutover sequence

The safest default is a blue/green issuer cutover after client modernization.

1. Freeze administrative writes for the approved window.
2. Confirm backup and rollback readiness.
3. Apply the already-rehearsed additive DDL.
4. Provision OpenIddict clients and scopes idempotently.
5. Deploy one immutable artifact to every green node.
6. Validate discovery, JWKS, readiness and synthetic flows off-path.
7. Apply the chosen old-token policy.
8. Switch traffic at the agreed boundary.
9. Run login, token, refresh, UserInfo, API and logout smoke tests.
10. Monitor agreed error and latency thresholds.
11. Unfreeze writes only after reconciliation passes.

Do not route by trying to parse `client_id` at a generic HTTP proxy; the value
may appear in query strings, form bodies or later protocol steps. Split
traffic only with a protocol-aware and tested design.

## Rollback

Rollback must be executable, not aspirational.

Trigger rollback on agreed conditions such as:

- discovery/JWKS failure;
- issuer or redirect mismatch;
- widespread token-validation failures;
- database readiness failure;
- signing-key mismatch;
- sustained login/token error increase;
- reconciliation outside tolerance.

The basic rollback is:

1. route traffic back to the legacy issuer;
2. confirm legacy signing, discovery and database health;
3. stop new administrative writes;
4. account for writes accepted during the green interval;
5. preserve diagnostic evidence without secrets or PII.

Additive OpenIddict tables can remain unused during rollback. Do not drop them
under incident pressure.

## Security rules for migration artifacts

Public repository artifacts must never contain:

- connection strings with credentials;
- OAuth client secrets;
- API keys or introspection secrets;
- private keys, PFX files or passwords;
- raw authorization codes or tokens;
- password hashes or personal claims;
- internal IP addressing or jump-host commands;
- production row dumps;
- organization-specific traffic/user counts.

Safe public artifacts include:

- schema definitions with no rows;
- placeholder client manifests;
- aggregate test expectations derived from a synthetic fixture;
- generic runbooks;
- public protocol metadata;
- redacted error types and stack locations.

Run secret scanning on:

- the complete candidate commit;
- untracked files;
- reachable Git history;
- CI after push.

## Migration gates

### Database and provider

- [ ] Supported MariaDB/EF/provider combination selected.
- [x] Shared table mapping is explicit.
- [x] Migration history is isolated.
- [x] Empty-database SQL is reproducible.
- [x] Additive legacy SQL is fail-fast.
- [x] Schema-only MariaDB rehearsal is automated.
- [ ] Rehearsal against a disposable real backup is repeatably green.

### Clients and protocol

- [ ] Every active client has an owner and final state.
- [ ] Implicit/hybrid/password consumers are migrated or retired.
- [ ] Confidential clients have newly issued credentials.
- [ ] PKCE S256 is enforced where applicable.
- [ ] Redirect, logout and CORS allowlists are verified.
- [ ] Token format is validated by every resource server.
- [ ] Old refresh/reference-token policy is approved.

### Runtime and operations

- [ ] Signing/encryption key distribution is tested.
- [ ] JWKS overlap and rotation are tested.
- [ ] Cookie/reauthentication policy is approved.
- [ ] Proxy and forwarded headers are verified end to end.
- [ ] Management parity or temporary legacy administration is approved.
- [ ] Backup, cutover and rollback rehearsals are complete.
- [ ] No migration step depends on secrets embedded in source control.

The migration remains **NO-GO** while any required gate is open.

## Implementation log

Keep entries generic and evidence-based.

### 2026-07-24

- Established one executable Server with STS and Management modules.
- Added explicit shared Identity/OpenIddict schema mappings.
- Added an isolated migration-history table.
- Added canonical empty and additive legacy SQL paths.
- Added a schema-only MariaDB compatibility fixture.
- Added local model/SQL contract tests.
- Added ephemeral MariaDB CI for empty and legacy paths.
- Confirmed a provider migration-lock incompatibility and kept provider
  selection as an open runtime gate.
- Applied canonical SQL through the MariaDB client while preserving exact
  EF-to-SQL comparison in tests.
- Added foreign-key reconstruction guards to the synthetic fixture.
- Passed build, test, dependency audit and secret scanning in CI.

## Primary references

- [OpenIddict documentation](https://documentation.openiddict.com/)
- [OpenIddict signing and encryption credentials](https://documentation.openiddict.com/configuration/encryption-and-signing-credentials.html)
- [OpenIddict token formats](https://documentation.openiddict.com/configuration/token-formats)
- [Pomelo.EntityFrameworkCore.MySql compatibility](https://github.com/PomeloFoundation/Pomelo.EntityFrameworkCore.MySql)
- [Oracle Connector/NET EF Core support](https://dev.mysql.com/doc/connector-net/en/connector-net-entityframework-core.html)
- [MariaDB maintenance policy](https://mariadb.org/about/)
- [ASP.NET Core Data Protection configuration](https://learn.microsoft.com/aspnet/core/security/data-protection/configuration/overview)
