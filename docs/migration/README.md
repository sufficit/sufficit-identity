# Database migration assets

These files prepare the database contract only. They do not authorize a
production deployment, canary, issuer change or frontend rollout.

The reusable end-to-end migration guide is
[`../plans/PLAN-LEGACY-CUTOVER-OPS.md`](../plans/PLAN-LEGACY-CUTOVER-OPS.md).

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

When the legacy and OpenIddict schemas live in separate databases on the same
MariaDB server, use `helpers/migrate-legacy-token-metadata.sh`. It is dry-run by
default and copies only identifiers and presentation metadata into revoked
`legacy_reference_token` rows. It never copies grant payloads or token values
and never changes the source database. Take a protected target backup before
running it with `--apply`.

### Post-cutover drift audit

When both databases remain writable during a staged rollout, run
`sql/090-audit-post-cutover-drift.sql` before retiring the legacy issuer. The
script opens a read-only consistent snapshot and compares the retained
`identity_legacy` database with the current `identity` database and the
immutable `users_backup_20260804_020900` cutover snapshot. Verify the database
names and cutover timestamp in the script before reusing it in another
environment.

The report distinguishes missing users from conflicting users, classifies
password and security-stamp changes three ways against the snapshot, checks
claims/logins/roles/user tokens, identifies client registrations requiring the
Duende-to-OpenIddict mapper and proves whether every eligible legacy reference
token has a revoked metadata tombstone. It never prints password hashes, token
values, grant payloads, e-mail addresses, phone numbers or client secrets.

Reconciliation after this audit must be additive and guarded by the cutover
snapshot:

- insert a legacy user only while its id, normalized e-mail and normalized user
  name remain absent from the current database;
- update a credential or security stamp only when the legacy value changed
  from the snapshot and the current value still equals the snapshot;
- insert missing claims and external logins by their semantic keys, without
  deleting current-only rows;
- keep current-only users, claims, tokens and protocol state untouched;
- run client registrations through the Duende-to-OpenIddict mapper and
  rehydrate confidential secrets from the protected raw secret;
- never copy usable authorization codes, refresh tokens, reference-token
  payloads, consents or server-side sessions between issuers. Preserve only
  revoked reference-token metadata tombstones.

```bash
mariadb --defaults-extra-file=/protected/mariadb.cnf \
  < docs/migration/sql/090-audit-post-cutover-drift.sql
```

The audited 2026-08-04 two-database rollout also has the one-shot
`sql/091-reconcile-post-cutover-identity.sql`. Its CHECK-backed preconditions
must match the corresponding `090` report exactly or the transaction aborts.
It inserts only missing Identity users/claims/logins and applies credential or
security-stamp changes only when the current value still equals the cutover
snapshot. Run the same input with its final `COMMIT` replaced by `ROLLBACK`
before applying it. Client registration and OAuth runtime artifacts remain
outside this script by design.

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
`070-add-scim-provisioning.sql`, followed by
`080-add-oidc-user-sessions.sql`, `081-add-ssf-streams-and-vault-keys.sql`
`082-add-security-hardening-state.sql` and the guarded
`083-enforce-normalized-email-uniqueness.sql` gate. The one-time retirement
script `092-retire-skoruba-identity-admin-api.sql` removes the superseded
Skoruba Admin API scope, revokes tokens issued from its authorizations and
removes only that permission from affected clients.

`094-add-protocol-state-entries.sql` is **required** and easy to miss: it
creates the `protocolstateentries` table that backs DPoP nonce challenges,
front-channel logout context and passkey ceremony tickets. These used to live
only in the in-process distributed cache, which silently stopped being shared
the moment a deployment ran more than one replica (evaluation 2026-08-30, F-4).
A host that provisions schema by SQL and skips this step does not fail at
startup — it fails on the first DPoP nonce challenge and on every passkey
ceremony, at runtime. Apply it before deploying that build.

That same evaluation made `Sufficit:Identity:DeploymentTopology` a **required
configuration key** outside Development: the production posture check refuses to
start with `deployment-topology-undeclared` until the deployment states its
shape (`SingleReplica`, `Clustered`, `BehindTrustedProxy` or
`ClusteredBehindTrustedProxy`). Configurations derived from
`src/server/appsettings.json.template` already declare it; one that trimmed the
key must add it back.

`011-add-openiddict-to-legacy.sql` intentionally does not use
`CREATE TABLE IF NOT EXISTS`: encountering an existing protocol table is drift
and must stop the rehearsal.

### Segredos de clientes confidenciais

O script de reconciliação não copia `clientsecrets.value` para
`applications.client_secret`: o valor legado é apenas `Base64(SHA-256)` e não
é aceito pelo OpenIddict 7, que usa PBKDF2 com salt. Para reidratar um cliente,
grave o segredo bruto em um arquivo protegido e execute o helper em modo de
simulação primeiro:

```bash
chmod 600 /protected/sufficit_web.secret
helpers/rehash-openiddict-client-secret.py \
  --defaults-extra-file /protected/mariadb.cnf \
  --database identity2 \
  --client-id sufficit_web \
  --secret-file /protected/sufficit_web.secret
```

Depois de validar a prévia, acrescente `--apply`. O helper só atualiza um
cliente confidencial cujo valor atual esteja ausente ou seja exatamente o hash
legado correspondente ao arquivo; ele recusa sobrescrever um segredo
desconhecido e nunca imprime o segredo ou o hash resultante.

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

## Additive hardening scripts

The numbered scripts below are safe to replay only when their documented
preconditions hold; they are additive and record their own markers in
`__sufficit_identity_migrations`:

- `082-add-security-hardening-state.sql` adds the metrics, SSF, CIBA, DPoP and
  Management draft state required by the current hardening code.
- `083-enforce-normalized-email-uniqueness.sql` emits only SHA-256 hashes and
  counts for duplicate normalized e-mails, aborts while any collision exists,
  and then adds the nullable unique index `UX_users_normalizedemail`.

Resolve every collision from the redacted report through the operator workflow
before running `083`; the script never selects or deletes an account.

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
