# Deployment configuration

## Persistent OpenID Connect certificate

The OpenIddict signing/encryption certificate is persistent cluster state. Its
canonical location is `/etc/sufficit/identity/certificate.pfx`, owned by
`root:www-data` with mode `0640`. Every Identity replica behind the same issuer
must contain the exact same file. It must not be replaced with a node's TLS
certificate and must not be generated independently on each replica.

`helpers/prestart.sh` copies the canonical certificate into the active release
before startup because the current production configuration references the
release-relative `certificate.pfx`. A production startup fails closed when
neither the persistent file nor an explicitly supplied release certificate is
available. Development may still generate a local self-signed certificate.

Before switching a release, verify all replicas report one checksum:

```bash
sha256sum /etc/sufficit/identity/certificate.pfx
```

After the rolling restart, query each replica directly and verify the same
`kid` is published from `/.well-known/openid-configuration/jwks`. A differing
`kid` causes intermittent signature-validation failures whenever discovery and
token issuance hit different nodes.

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
- leaves administrative MFA enforcement off until administrators have enrolled
  and completed a real two-factor login;
- leaves DPoP and CIBA off while their nonce/replay and pending-request stores
  are process-local.

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

For administrative MFA, first enroll at least two operators, store recovery
codes offline and verify that a real two-factor session carries `amr=mfa`.
Then apply the explicit gate:

```bash
/opt/sufficit-identity/helpers/security-rollout.sh enforce-mfa --confirmed
/opt/sufficit-identity/helpers/activate-release.sh --current
```

Emergency rollback is explicit and does not affect CSP:

```bash
/opt/sufficit-identity/helpers/security-rollout.sh disable-mfa
/opt/sufficit-identity/helpers/activate-release.sh --current
```

Every modifying command preserves the pre-command file as
`/etc/sufficit/identity/hardening.env.bak`. DPoP/CIBA do not have rollout
commands intentionally: before a second Identity replica or production CIBA,
replace the process-local stores with an atomic shared implementation such as
Redis, then add a separately reviewed enablement step.

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
