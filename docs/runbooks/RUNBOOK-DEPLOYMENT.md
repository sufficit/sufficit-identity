# Deployment configuration

## Persistent OpenID Connect certificate

The OpenIddict signing/encryption certificate is persistent cluster state. Its
canonical location is `/etc/sufficit/identity/certificate.pfx`, owned by
`root:www-data` with mode `0640`. Every Identity replica behind the same issuer
must contain the exact same file. It must not be replaced with a node's TLS
certificate and must not be generated independently on each replica.

Certificate and release preparation is a privileged deployment operation. The
root-owned `/usr/libexec/sufficit-identity/bootstrap-release.sh` copies the
persistent certificate into a candidate release, persists an existing release
certificate when necessary, and makes the complete release root-owned and
non-writable by the service account. Only Development may create a self-signed
certificate; its password is random and stored in
`/etc/sufficit/identity/certificate.password` as `root:www-data` mode `0640`.

At runtime, `ExecStartPre` invokes the separately installed, root-owned
`/usr/libexec/sufficit-identity/prestart.sh` as `dotnetuser`. It performs only
read-only validation: active release, certificate presence/ownership/mode,
private-key readability when a protected password source is available, and
absence of group/other-writable release paths. Any failure blocks startup.

Before switching a release, verify all replicas report one checksum:

```bash
sha256sum /etc/sufficit/identity/certificate.pfx
```

After the rolling restart, query each replica directly and verify the same
`kid` is published from `/.well-known/openid-configuration/jwks`. A differing
`kid` causes intermittent signature-validation failures whenever discovery and
token issuance hit different nodes.

For rotation, configure ordered `Certificates:SigningPaths` and
`Certificates:EncryptionPaths`. The first unique certificate is active for new
artifacts; the remaining certificates stay available during the validation or
decryption overlap. Enable `RequirePurposeSeparation` only after distinct
signing and encryption material has been distributed to every replica.

## Dedicated database migration

Outside Development, the HTTP process rejects `Database:AutoMigrate=true`.
Apply pending EF migrations through the dedicated oneshot unit before switching
the application release:

```bash
systemctl start sufficit-identity-migrator.service
systemctl status sufficit-identity-migrator.service --no-pager
```

The unit executes `Sufficit.Identity.Server.dll --migrate-only` as the
unprivileged service account. The migrator validates the same release and
certificate invariants as the web process and obtains the MariaDB advisory lock
`sufficit_identity_schema_migrator`, so two deployment jobs cannot migrate the
schema concurrently. A non-zero unit result blocks release activation; inspect
the journal and fix the migration instead of starting the web service against a
partially upgraded schema.

### Normalized e-mail uniqueness gate

Before enabling the normalized-email unique index, run the additive script from
an approved database session:

```bash
mariadb --defaults-extra-file=/protected/mariadb.cnf identity \
  < docs/migration/sql/083-enforce-normalized-email-uniqueness.sql
```

The first result set contains only a SHA-256 hash and the number of colliding
rows. The script aborts before creating the index when any collision exists.
For each reported hash, an authorized operator must use the internal account
administration workflow to inspect the corresponding account IDs (never export
the e-mail address), select the canonical account according to the retention
policy, and change or remove the duplicate address in an audited transaction.
Do not merge users, reset credentials, or delete an account as an ad-hoc SQL
operation. Re-run the script after every correction; only a zero-collision run
creates `UX_users_normalizedemail` and records its migration marker. The script
is safe to replay after a successful run.

### Retired Skoruba Admin API scope

The legacy `skoruba_identity_admin_api` scope is no longer a supported API
surface. After taking the normal production backup, run the idempotent cleanup
script from an approved database session:

```bash
mariadb --defaults-extra-file=/protected/mariadb.cnf identity \
  < docs/migration/sql/092-retire-skoruba-identity-admin-api.sql
```

The script revokes valid tokens tied to authorizations that granted the old
scope, removes only that item from application permissions and authorizations,
and deletes the scope row only when both its historical ID and name match.
The management and provisioning layers reject the retired name so a later
release cannot recreate it. Verify zero rows for the scope, old permission,
old authorization grant and valid token before activating the release.

## Serialized production activation

Never switch `/opt/sufficit-identity` and call `systemctl restart` directly in
separate commands. Activate a prepared release through the versioned helper:

```bash
/opt/sufficit-identity/helpers/activate-release.sh \
  /opt/sufficit-identity.releases/<release>
```

The helper holds `/run/lock/sufficit-identity-deploy.lock`, rejects overlapping
deploys, changes the release symlink atomically, waits for the direct nginx
health endpoint and rolls the symlink back when the new release does not become
healthy. For a configuration-only restart of the active release, use:

```bash
/opt/sufficit-identity/helpers/activate-release.sh --current
```

## test-environment test environment

The versioned source of truth for the Sufficit Identity nginx virtual host in
the test environment is
[`helpers/nginx-identity.conf`](../../helpers/nginx-identity.conf). The installed
copy is `/etc/nginx/sites-available/sufficit-identity-test`, enabled through
the corresponding symlink under `/etc/nginx/sites-enabled`. This isolated test
virtual host listens on HTTPS port `5001`; smoke checks must use
`https://app.example.com:5001`. Port 443 belongs to other/legacy
virtual hosts on the shared server and is not a valid Identity test endpoint.

Operational changes must be made in the repository first, validated with
`nginx -t`, deployed to the installed path and committed. This keeps the
server from becoming an untracked second source of truth.

The OpenIddict scope/resource mapping used by the local Sufficit Endpoints is
versioned in
[`manifests/test-environment-endpoints.v1.json`](manifests/test-environment-endpoints.v1.json).
The `directives` scope keeps the MCP audience and also names
`SufficitEndpointsIntrospection` as a resource. OpenIddict then allows that
confidential resource server to introspect the reference tokens issued to the
Blazor client. Apply the manifest through the provisioning preview/apply flow;
for an emergency database-level rollout, preserve the complete scope row and
change its concurrency token before restarting Identity. Tokens issued before
the change retain their old audiences, so validation must use a fresh login or
refresh token after the rollout.

### Migração gradual do formato de access token

`Tokens:UseReferenceAccessTokens` é apenas o fallback para integrações ainda
não inventariadas. Migre sem flag day com `AccessTokenFormatsByResource` ou,
quando o contrato realmente pertencer ao chamador, com
`AccessTokenFormatsByClient`. Valores aceitos são `Reference` e `Jwt`; regras
por recurso têm precedência e recursos conflitantes na mesma emissão são
negados.

Antes de configurar `Jwt`, confirme que o resource server valida o JWS pelo
JWKS público, fixa issuer/audience e não depende de revogação imediata por
introspecção. Emita um token novo, valide-o localmente e também via introspecção,
depois observe erros até o maior lifetime. Para rollback, remova a regra exata:
novas emissões retornam ao fallback, enquanto tokens anteriores permanecem
válidos até expirar.

The application owns authentication state. In particular, passkey
authentication tickets are protected and stored server-side by
`PasskeyAuthenticationTicketStore`; nginx must not be made responsible for
accommodating oversized passkey response cookies. The
`large_client_header_buffers` directive in the virtual host only covers large
request headers received from clients.

After deployment, compare the effective virtual host with the versioned file
and run:

```bash
nginx -t
systemctl restart nginx
```

Only restart nginx after the syntax check succeeds. On `test-environment`, do not
replace the restart with a reload: the packaged nginx has previously crashed
with `SIGSEGV` while rebuilding configuration state during a reload.

## Security rollout

`helpers/install.sh` creates `/etc/sufficit/identity/hardening.env` from the
versioned `helpers/hardening.env.template` on first installation. Subsequent
installs preserve every existing value and append only newly introduced keys
with their secure template defaults, so a deployment cannot silently roll CSP
or MFA backwards while new gates remain explicit. The systemd unit reads the
file through an optional `EnvironmentFile` directive. This vendor/application
namespace keeps host configuration for multiple Sufficit services grouped
under `/etc/sufficit`. For compatibility, the installer copies a legacy
`/etc/sufficit-identity/hardening.env` into the new location when necessary,
without deleting the legacy file.

The initial state deliberately does the following:

- enables the application `/connect/token` limiter and fails startup when no
  trusted proxy network is configured;
- emits CSP in Report-Only mode and sends same-origin reports to
  `/security/csp-report`;
- requires MFA evidence for the sensitive management, SCIM, personal-token and
  SSF transmitter surfaces by default. Before enabling a surface, enroll the
  operators, store recovery codes offline and verify that a real two-factor
  session carries `amr=mfa`; machine-to-machine exceptions require separate
  review and must retain their client allow-list;
- keeps Management tenant access fail-closed until every operator has an
  explicit stable-subject assignment. Before enabling or upgrading Management,
  add one protected entry per tenant to `hardening.env`, for example
  `Sufficit__Identity__Management__Authorization__TenantAccess__SubjectTenants__<operator-sub>__0=global`;
- leaves DPoP and CIBA off until their client cohorts are provisioned and a
  multi-replica deployment has a real shared `IDistributedCache`; DPoP replay
  and CIBA pending state remain database-authoritative, while nonce/session
  cache behavior still depends on the configured distributed cache.

The CSP report endpoint accepts the browser's legacy `application/csp-report`
format and the Reporting API JSON format. It logs only sanitized fields, with
URL query strings, fragments and credentials removed. Nginx caps each body at
16 KiB and rate-limits the endpoint.

Inspect rollout state:

```bash
/opt/sufficit-identity/helpers/security-rollout.sh status
```

Prepare or reset CSP calibration:

```bash
/opt/sufficit-identity/helpers/security-rollout.sh prepare-csp
/opt/sufficit-identity/helpers/activate-release.sh --current
```

Exercise login, registration, consent, logout, device flow, MFA, external
providers and the Blazor Server circuit. Review the Identity journal for
`CSP violation` events. After legitimate violations have been eliminated,
enable enforcement:

```bash
/opt/sufficit-identity/helpers/security-rollout.sh enforce-csp
/opt/sufficit-identity/helpers/activate-release.sh --current
```

To re-assert all sensitive-scope MFA gates after a configuration change, first
enroll at least two operators, store recovery codes offline and verify that a
real two-factor session carries `amr=mfa`. Then apply the explicit gate:

```bash
/opt/sufficit-identity/helpers/security-rollout.sh enforce-mfa --confirmed
/opt/sufficit-identity/helpers/activate-release.sh --current
```

Emergency rollback is explicit and does not affect CSP:

```bash
/opt/sufficit-identity/helpers/security-rollout.sh disable-mfa --confirmed
/opt/sufficit-identity/helpers/activate-release.sh --current
```

Every modifying command preserves the pre-command file as
`/etc/sufficit/identity/hardening.env.bak`. DPoP/CIBA do not have rollout
commands intentionally: before a second Identity replica or production CIBA,
configure a shared `IDistributedCache` such as Redis, set
`DistributedCache:RequireShared=true`, verify database-backed replay/pending
state across replicas, and add a separately reviewed enablement step.

The Nginx virtual host selects per-IP limits by location: strict zones protect
interactive authentication, protocol/token endpoints and CSP reports; ordinary
application requests use the general zone; versioned `/_content/` and
`/_framework/` assets use a separate high-volume zone sized for the browser's
parallel first-render burst. Never move the general limit back to `server`
scope, where it would be inherited by CSS, fonts and Blazor scripts and could
leave the management UI unstyled. These are edge controls; account lockout and
the application token limiter remain active as defense in depth. The
configuration deliberately avoids conditional `map` keys because the nginx
version on `test-environment` proved unstable while rebuilding a large variables
hash. Because `limit_req_zone` is an `http`-context directive, install the
complete virtual-host file under `sites-available` as documented above rather
than copying only its `server` block.
