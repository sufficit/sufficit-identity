# Database migration assets

These files prepare the database contract only. They do not authorize a
production deployment, canary, issuer change or frontend rollout.

The reusable end-to-end migration guide is
[`../plans/PLAN-LEGACY-CUTOVER.md`](../plans/PLAN-LEGACY-CUTOVER.md).

## Supported paths

The database remains the existing MariaDB database. Nothing in this procedure
migrates data to MySQL, creates a second production source of truth or requires
a database server on a developer machine.

### Empty database

Use `sql/001-create-empty-database.sql`. It is generated from the canonical EF
model and creates the shared ASP.NET Core Identity tables, Data Protection,
passkeys, the OpenIddict tables, the generic branding-theme table and the
append-only administrative audit table, plus the SCIM profile/group tables.

Regenerate it with:

```bash
dotnet tool restore
dotnet tool run dotnet-ef migrations script \
  --project src/core/Sufficit.Identity.Core.csproj \
  --startup-project src/server/Sufficit.Identity.Server.csproj \
  --output docs/migration/sql/001-create-empty-database.sql
```

Do not add `--idempotent`: the checked-in contract intentionally matches the
normal ordered migration script and MariaDB-compatible syntax exactly.

### Existing Skoruba/Duende database

The recommended future layout keeps the existing ASP.NET Core Identity tables
as the single source of truth and adds only the four OpenIddict protocol
tables.

1. Use `fixtures/legacy-schema-mariadb-10.4.sql` for the schema-only CI
   rehearsal.
2. Restore a production backup into a separate isolated rehearsal database
   before a migration window is approved.
3. Run `sql/010-preflight-legacy.sql`.
4. Abort if the preflight returns any row.
5. Run `sql/011-add-openiddict-to-legacy.sql` only against the rehearsal copy.
6. Run `sql/012-preserve-legacy-reference-token-identifiers.sql` to create
   revoked metadata-only tombstones for legacy API reference tokens.
7. Run the schema contract tests and data reconciliation.
8. Repeat from a fresh backup to prove the process is deterministic.

For the database-only real-backup gate, copy the SQL directory and a protected
logical backup to the database host, then run:

```bash
MARIADB_SOCKET=/path/to/mysql.sock \
  ./rehearse-real-backup.sh /protected/path/identity.sql.gz 3
```

The script accepts only a local gzip backup with the expected 39-table legacy
schema. It creates uniquely named `identity_rehearsal_*` databases, performs
fresh restores, verifies shared-schema/data fingerprints and token-policy
invariants, and drops every disposable database through an exit trap. It has
no remote-host defaults, embedded password or production database target.

Deployments already running the canonical model apply later additive steps in
order: `050-add-branding-themes.sql`,
`060-add-management-audit-events.sql` and
`070-add-scim-provisioning.sql`.

`011-add-openiddict-to-legacy.sql` intentionally does not use
`CREATE TABLE IF NOT EXISTS`: encountering an existing protocol table is drift
and must stop the rehearsal.

The checked-in fixture represents a legacy Duende/Skoruba schema on MariaDB
10.4.34. It has 39 table definitions, but no rows, credentials, views,
routines or data-dependent `AUTO_INCREMENT` counters. Because table
definitions are stored alphabetically rather than in foreign-key dependency
order, the fixture disables `FOREIGN_KEY_CHECKS` only for its reconstruction
session and re-enables it before preflight.

The eventual deployment operation, after all remaining gates are closed, is
therefore an additive schema change in the same MariaDB database:

- `users`, `roles`, claims, external logins, user tokens, passkeys and Data
  Protection keys remain in place;
- the existing Duende tables remain available to the legacy service during
  the transition;
- `applications`, `authorizations`, `scopes` and `tokens` are added for
  OpenIddict;
- `__sufficit_identity_migrations` records only the new model;
- clients and scopes are reconciled from a versioned manifest; Duende grant
  rows are not converted into usable OpenIddict credentials;
- only legacy `reference_token` identifiers are copied as revoked tombstones,
  without payload, serialized grant data or session identifiers, so account
  APIs can explain that regeneration is required;
- the original reference-token rows are marked consumed and receive the stable
  `[identity-upgrade]` description prefix during the same cutover, keeping
  their identifiers visible to the temporary compatibility API while making
  them unusable at the legacy issuer too.

Browser sessions, refresh tokens, authorization codes and usable reference
tokens are deliberately not preserved. Users reauthenticate and regenerate
API tokens. The tombstones exist only for identifier continuity and always
introspect as inactive.

The previous two-database `run-migration.sh` helper was removed. It targeted
the superseded `identity2` copy architecture, embedded connection defaults and
could recreate a database. The supported path is now exclusively the guarded,
additive same-database procedure described above.

## Migration history

The new model owns `__sufficit_identity_migrations`. It must never reuse the
legacy `__efmigrationshistory`, which contains Skoruba/Duende migrations.

The additive script marks the canonical `Initial` migration as applied after
creating the four OpenIddict tables. Existing users, roles, claims, logins,
tokens, passkeys and Data Protection keys are not copied or changed.

## CI enforcement

The build workflow starts an ephemeral `mariadb:10.4.34` service matching the
configured compatibility baseline, applies the checked-in canonical SQL with
the MariaDB client in that container and then runs two schema integration
paths.
The local contract test regenerates the SQL from the EF migration and requires
an exact match, so the tracked script cannot drift from the model.

1. **Empty database:** verifies there are no pending migrations, the isolated
   migration history contains every canonical migration, all 20 expected tables
   exist and critical OpenIddict/passkey/SCIM indexes and types match.
2. **Legacy rehearsal:** creates the fixed
   `identity_legacy_rehearsal` database on the loopback CI service, loads the
   39-table fixture, requires a zero-row preflight, applies the additive
   script, verifies the five new tables/history and proves that the columns,
   indexes and foreign keys of all shared Identity tables are byte-for-byte
   unchanged. The test drops the rehearsal database in `finally`.

When no connection is supplied, developer machines do not start or require a
local MariaDB service. In GitHub Actions, absence of the CI connection
variable fails the integration test instead of silently skipping it.

The destructive rehearsal guard requires all three conditions: CI mode, an
explicit opt-in variable and a connection to `identity_contract` on loopback.
It cannot accept a remote hostname or arbitrary database name.

The runtime and migration tests use the Sufficit Pomelo EF Core 10 fork with
explicit MariaDB 10.4 compatibility; this remains the same MariaDB deployment,
not a database-engine migration.

## Secrets

These assets contain no connection strings, credentials, client secrets,
password hashes, tokens or personal data. Supply database access through the
approved secret mechanism at execution time.
