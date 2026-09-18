# Genius/Fleet: existing Sufficit login

User request: reuse the authenticated Genius account and extend the intended
resource audience instead of requiring a personal API token.

## Delivery

- Explicit `FirstPartyUserScopes` mapping, empty by default, applied only to user
authorization/device grants and refresh. Each added scope must be registered and
permitted to that exact client. Machine grants and token exchange are unchanged.
- Production Genius registration additively received `scp:fleet.api`; the existing
scope maps to `sufficit_fleet`. Existing subject, scopes, resources, entitlements
and tenant authorization are preserved.
- Three Identity nodes (eveo, apoint, castrum) run
`6657e423d58f00d318d7af9ce8f6de7881600452`, prepared with configuration-preserving
helpers and activated through the coordinated cluster wrapper. All report
Healthy/Ready with identical certificate and JWKS hashes.
- Legacy installation directories were moved intact under the releases root and
replaced by release links under the shared cluster lease and per-node locks.
The live processes remained healthy. Previous binaries/configuration are retained
as `legacy-20260917-9e0e7cba-pruning` for rollback.
- Mapping is in each active `appsettings.Production.json`, backed up to protected
`/etc/sufficit/identity/pre-fleet-sso-production.backup`. An attempted systemd
Environment assignment was ignored because client-ID hyphens are invalid in an
environment variable name; removed and documented. A separate coordinated restart
loaded the JSON configuration. No credentials entered the release archive or logs.

## Evidence

- Full local suite: 1355 tests passed. Server build: zero warnings/errors.
- Primary CI on contingência linux-ci/LXC2210: exact SDK 10.0.302 installed alongside
existing SDKs; 1355 passed, 1 environment-dependent integration test skipped,
1356 total. Code revision 0d62baf equals deployed code (subsequent docs only).
- Legacy locally enrolled Genius refreshed its existing login without an explicit
scope request, then `fleet_specialists` returned all six authorized specialists.
No new enrollment or personal token was created. Test conversation
`a810e443-f711-4d49-b78d-10a23e0c40c1`; real Fleet mission accepted as
`01a0b12e-43cf-791a-afd3-0cbdbcaefe57`: Completed, created 21:03:14Z,
started 21:03:18Z, ended 21:03:28Z. Specialist text returned to the original chat.
- Automated regression also proves unchanged subject/original audience,
registration and permission requirements, other-client isolation and no implicit
scope for client_credentials.

## References and limits

Identity issue #73, PR #74; Genius issue #828, PR #829.
See `docs/runbooks/RUNBOOK-FIRST-PARTY-USER-SCOPES.md`.
Removing the server mapping does not revoke previously granted permissions;
revoke affected grants when withdrawing that access. Deployment is the isolated
PR build; unrelated canonical Identity changes remain untouched.
