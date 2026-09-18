# Deploy of the conformance fixes and the Fleet SSO merge

Release `20260918T120021Z-1feceae`, revision `1feceae`, activated on the three
production nodes on 2026-09-18 12:00 UTC at the user's request.

## What production was running before

`6657e42`, from the branch `feature/genius-fleet-sso` — **not from `main`**. It
descends from `5b31f62` (the first half of A12) and adds
`FirstPartyUserScopePolicy`, which grants explicit first-party user scopes on
login and refresh. Deploying `main` as it stood would have removed that from
production.

The branch was merged into `main` first (`1feceae`), so the two now agree. The
merge was built and tested before publishing: 0 warnings, 1379 tests.

## What the deploy carries

Only three commits of server behavior beyond what was already in production:
`b3da52a`, `45ed353`, `039836e` — the OpenID conformance work. The rest of the
formerly undeployed queue had already gone out with `6657e42`, migration 099
included, so **no migration was pending** (`git diff 6657e42..main --
src/core/Migrations` is empty).

Behavior that changes for callers, with FAPI 2, DPoP and JAR **off** in
production (only mTLS is enabled, on eveo), so none of the profile work touches
live traffic:

- UserInfo refuses an access token in the query string (RFC 6750 2.3). Deployed
  with the new default, by the user's explicit choice;
  `Sufficit:Identity:Tokens:AllowAccessTokenInQueryString=true` restores the old
  behavior without a new release if a consumer turns out to need it.
- `prompt=login` now reauthenticates instead of reusing a recent session.
- A token request without `code_verifier` answers `invalid_grant` instead of
  `invalid_request`, for clients that had to use PKCE.
- `openid` is no longer filtered by the client's scope permissions, so requests
  that were silently downgraded to plain OAuth get their `id_token`.
- `phone` and `address` are advertised and answered by UserInfo.

## How it went

`prepare-cluster-release.sh` staged the archive on the three nodes, inheriting
each node's four configuration files from the previous release.
`activate-cluster-release.sh` ran eveo alone first; discovery was checked on it
(`phone`/`address` in `scopes_supported`,
`token_endpoint_auth_signing_alg_values_supported` = PS256/ES256/RS256, the new
claims, DPoP still unannounced) before apoint and castrum were activated
together. The uniformity gate and `verify-production-cluster.sh` both report the
three nodes active, Healthy/Healthy at `1feceae` with the same certificate.
Public discovery and JWKS answer 200. No error entries in the journal of any
node in the ten minutes after activation.

The packaging helper needed `SufficitUseLocalSui=false` in the environment: it
publishes with `--no-restore` and does not pass the switch itself, so the local
`sufficit-blazor-ui` sibling collided with the NuGet package (CS1704).
