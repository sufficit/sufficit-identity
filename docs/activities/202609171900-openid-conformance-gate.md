# OpenID conformance suite as a repeatable gate (A12)

Evaluation item **A12**: an external proof of protocol conformance, not only the
repository's own tests. `conformance/` now builds a disposable environment from
the working tree and runs an OpenID Foundation certification plan against it; the
`OpenID conformance` workflow runs it nightly and on demand.

## What was built

| Piece | Role |
|---|---|
| `conformance/run.sh` | Clones the suite scripts at `CONFORMANCE_SUITE_TAG`, generates throwaway credentials, renders the plan configuration, brings the environment up, runs the plan, exports results and tears everything down |
| `conformance/docker-compose.yml` | MariaDB, the server image built from `Dockerfile`, an HTTPS front for the issuer, the suite (MongoDB + server + nginx), the seeder and the runner |
| `conformance/seeder` | Test-only tool, outside the solution, that creates the user and the two static clients through the same managers the server uses |
| `conformance/config/` | Plan template plus the accepted-failure and accepted-skip lists |
| `.github/workflows/conformance.yml` | Nightly schedule and `workflow_dispatch`, results uploaded as an artifact |

Deviations from production defaults are stated in `conformance/README.md`
(PKCE not required, implicit consent on the static clients, management and Vault
UI surfaces not hosted), so a green plan is never read as more than it proves.

## Server defects the suite found

Both were behavior the repository's own tests did not cover, and both are fixed
with a regression test:

1. **`openid` filtered by client permissions.** `GetRequestedScopesAsync` dropped
   any scope the client had no `scp:` permission for, `openid` included.
   OpenIddict does not enforce a `scp:openid` permission, so the request stayed
   valid — as plain OAuth: the token response carried no `id_token`
   (OIDCC-3.1.3.3). Covered by `OpenIdScopePermissionTests`.
2. **`prompt=login` did not reauthenticate.** `AuthorizationReauthenticationPolicy`
   only looked at `max_age`, so a recent session was reused and the second
   `id_token` repeated `auth_time` (OIDCC-3.1.2.1, `oidcc-prompt-login`). The
   parameter now requires a new credential ceremony, cleared by the same receipt
   `max_age=0` uses. Covered by `AuthorizationReauthenticationPolicyTests` and
   `AuthorizationReauthenticationIntegrationTests`.

3. **`address` advertised and never answered, `phone` never advertised.**
   Discovery listed the `address` scope while UserInfo returned nothing for it,
   and the `phone` scope was absent even though ASP.NET Core Identity already
   stores the number and its confirmation. UserInfo now answers both, `address`
   as the JSON object of OIDC Core 5.1.1. Covered by
   `UserInfoPhoneAddressTests`.

## Harness findings that are not server defects

- Error-path modules (`oidcc-response-type-missing`,
  `oidcc-ensure-registered-redirect-uri`, the request-object ones) keep the user
  on the OP's own error page and ask for a screenshot of it, which is exactly
  what the server renders. The browser configuration was waiting for a callback
  that correctly never comes, so the callback task is optional and an error page
  satisfies the screenshot placeholder.
- `oidcc-prompt-login` also wants a screenshot, of the second login page; the
  login task uploads one whenever a placeholder is pending.
- `oidcc-server-client-secret-post` needs its own static client entry
  (`client_secret_post` in the plan configuration); OpenIddict accepts both
  client authentication methods for the same client, so it reuses client 1.

## Result

`oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]`,
35 modules, exit code 0:

| Result | Modules |
|---|---|
| PASSED | 20 |
| WARNING, accepted in `expected-failures.json` | 8 |
| REVIEW (the suite asks a human to look at an uploaded screenshot) | 4 |
| SKIPPED, accepted in `expected-skips.json` | 2 |
| FAILED or INTERRUPTED | 0 |

The accepted warnings are: OpenIddict's own `oi_tkn_id`/`oi_au_id` in the
`id_token`; identity claims in the `id_token` for their scopes, which the
product's clients depend on; the suite's requirement that a scope return every
one of its standard claims; `acr` not echoing a voluntary `acr_values`; and the
unimplemented `claims` request parameter. Each entry in the file says why.

Two environment settings were needed to make the plan run end to end, both
recorded in `conformance/README.md`: the rate limiter is off, because a whole
plan runs from one address in about two minutes and the last modules were
answered with `temporarily_unavailable`; and JAR is on, because with the feature
off OpenIddict refuses a `request` parameter while extracting the request —
before the redirect URI is validated — so the error cannot be returned to the
client as OIDCC-3.1.2.6 requires. With JAR on, discovery announces which signing
algorithms are accepted and the suite skips the unsigned request object modules.

## Not deployed

The fixes are on `main` with CI green and are **not** deployed: the user is
traveling and cannot verify production. They join the other undeployed commits
listed in `docs/activities/202609132250-deploy-evaluation-remediation.md`.
