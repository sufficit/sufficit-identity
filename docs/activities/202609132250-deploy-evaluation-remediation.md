# Deploy of the 2026-09-12 evaluation remediation

On 2026-09-13, at the user's request, production moved from the CSP hotfix
`d35f6bc` (built on `03243f3`) to `main` at
`e41e2e1c2e62faee59ea09333957a74b0e0988b9`: token exchange delegation,
ID-JAG, per-request session stamp validation, static assets without
authentication, product-neutral vocabulary, localized management console,
identity module composition, CIBA polling at the token endpoint and
per-registrant DCR initial access tokens with their console page.

## Preconditions checked on every node

- `FullAdministratorRoles` present in `appsettings.Production.json`.
- The retired shared DCR token (`identity/dcr/initial-access-token`) absent from
  `vault-secrets.env` and `hardening.env`. DCR runs with
  `RequireInitialAccessToken=false` (anonymous interactive profile), so the new
  token requirement does not change registration behavior.
- `ExternalIdentities:RequireVerifiedEmail` defaults to true, so the new
  posture finding does not fire.
- No other repository under `/mnt/sufficit` reads `urn:sufficit:acr`,
  `urn:sufficit:claim:address`, `urn:sufficit:credential-type` or
  `urn:sufficit:token:`.

## Compatibility configuration

Values that were hard-coded before this release and are configuration from it
on were pinned to their previous values with the systemd drop-in
`/etc/systemd/system/sufficit-identity.service.d/50-evaluation-compat.conf` on
all three nodes, installed before activation:

| Setting | Value | Why |
|---|---|---|
| `AuthenticationContext:AcrPrefix` | `urn:sufficit:acr:` | `acr` emitted to relying parties |
| `PersonalTokens:ClientId` | `SufficitAPIUserAccess` | `client_id` of new personal access tokens |
| `Branding:ProductName` | `Sufficit Identity` | e-mail subjects and authenticator issuer |

The running process environment on each node contains the three values.

## Artifact

- Isolated worktree at `e41e2e1`, `dotnet restore --locked-mode` and publish
  with `-p:SufficitUseLocalSui=false`, so the release uses the locked
  `Sufficit.Blazor.UI` 2.26.911.2250 that CI tests.
- Archive SHA-256
  `63c8f658bc021bde5b96ce52c4a8101c117c02cbce112c89606087f613074c66`.
- CI: `f5207e0` (same runtime code plus a test-only fix) passed build with
  warnings as errors and the full suite. The earlier runs on `e754c2f` and
  `e41e2e1` failed on a CS8604 warning and on the MariaDB table count; both were
  fixed before activation.

## Migration

`20260914012253_AddDcrInitialAccessTokens` was applied once, on eveo-apps, with
the staged binary (`--migrate-only`, service identity and environment, no HTTP
host). The production posture check passed in that run. The migration row and
the `dcrinitialaccesstokens` table were confirmed in the databases of all three
nodes. Log: `/var/log/sufficit-identity-migration-dcr-20260914.log` on
eveo-apps (0600).

## Activation

The servers still use the physical `/opt/sufficit-identity` layout, which the
release wrappers refuse, so the procedure of the previous deploys was used:
staging per node with the active `appsettings*.json` and certificates copied
and compared by content, owner and mode; deploy lock per node; stop, move,
start; readiness gate; automatic rollback.

| Node | Healthy (BRT) | Downtime | Restarts |
|---|---|---|---|
| eveo-apps | 22:47:30 | 6 s | 0 |
| apoint-apps | 22:50:05 | 4 s | 0 |
| castrum-apps | 22:50:22 | 2 s | 0 |

### Incident

The first attempt on apoint-apps failed its preflight: the archive carried
group-writable files because the workstation umask was 0002, and the preflight
refuses group- or other-writable release paths. The readiness gate rolled the
node back to `d35f6bc` automatically; the service was down on that node for
about a minute while the other two served traffic. Group and other write bits
were removed from the staged releases and apoint-apps was activated again.
eveo-apps had started with the same files because its drop-in runs the release
preflight with `+-` (failure ignored); the bits were removed there too and the
preflight now passes. `helpers/package-release.sh` normalizes modes before
packaging (`51504ad`).

Follow-up: the eveo-apps drop-in `10-dotnet10.conf` ignores preflight failures
(`ExecStartPre=+-...`), unlike castrum-apps. Aligning it is a separate
configuration change.

## Verification

- `helpers/verify-production-cluster.sh e41e2e1…`: uniform revision, service
  active, health and readiness Healthy; certificate
  `5e858b8d…410eefb` and JWKS `85d43862…aed769` unchanged from the previous
  release and equal on all nodes.
- Public discovery with issuer `https://identity.sufficit.com.br/`, public login
  and health 200; management redirects anonymous requests to sign-in.
- No error-priority journal entries after activation on any node.

## Rollback

Previous releases are kept as `/opt/sufficit-identity.before-eval-e41e2e1` on
each node. Roll back one node at a time: stop the service, move the active
directory aside, restore the backup, start and wait for readiness. The DCR
migration is additive and stays. The compatibility drop-in is harmless for the
previous binary.
