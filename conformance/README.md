# OpenID conformance environment

Runs the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)
against a disposable Sufficit Identity environment. It is the external proof
behind the protocol coverage claimed in `docs/rfc/`: the unit and integration
tests show the behavior the code intends, the suite shows how an independent
implementation sees it.

Nothing here is a deployment recipe. Every run builds the server image from the
working tree, generates fresh credentials, and removes the containers and
volumes afterwards.

## Run

```bash
conformance/run.sh
```

The default plan is the OpenID Connect Basic OP certification plan with discovery
and static clients. Another plan and configuration template can be passed as
arguments:

```bash
conformance/run.sh "<plan-name[variants]>" conformance/config/<template>.json
```

Requirements: Docker with Compose v2 and network access to pull the suite images
from `registry.gitlab.com/openid/conformance-suite` and to clone the suite scripts.

Useful variables:

| Variable | Default | Meaning |
|---|---|---|
| `CONFORMANCE_SUITE_TAG` | `release-v5.2.4` | Suite image and script version; both must match |
| `CONFORMANCE_RESULTS_DIR` | `conformance/results` | Exported plan results, rendered config and Identity log |
| `CONFORMANCE_KEEP` | unset | When set, keeps the containers running for inspection |

## Topology

| Service | Role |
|---|---|
| `db` | MariaDB 10.4.34, schema applied by the server's Development migration |
| `identity` | The server image built from `Dockerfile`, `ASPNETCORE_ENVIRONMENT=Development` |
| `identity-op` | nginx with a self-signed certificate, published as `https://identity-op.test/` |
| `seeder` | Test-only tool (`conformance/seeder`) that creates the user and two static clients |
| `mongodb`, `suite-server`, `suite-nginx` | The conformance suite, reachable as `https://localhost.emobix.co.uk:8443/` |
| `runner` | Runs `scripts/run-test-plan.py` from the suite checkout and exports the results |

Development is used because it provides ephemeral signing keys and no HTTPS
requirement inside the container; the issuer is a `.test` host, which the
Development host guard accepts. The database connection string reaches the
server and the seeder through `SUFFICIT_SECRET_DATABASE_CONNECTION_STRING`, the
same secret boundary production uses: the server refuses connection strings in
plain configuration.

## Deviations from production defaults

Stated explicitly so a result is never read as more than it proves:

- `Pkce:RequireForAllClients=false`: the OpenID Connect Basic profile does not
  send PKCE. Production keeps PKCE mandatory for every client.
- The static clients use implicit consent, so the suite does not need to automate
  a consent page.
- The management console and Vault UI surfaces are not hosted
  (`UI:Management:Mode=None`, `UI:Vault:Mode=None`): they require the management
  API, and only the public sign-in UI takes part in OpenID Connect flows.
- `RateLimit:Enabled=false`: a full plan runs from one address in about two
  minutes and the limiter answered the last modules with
  `temporarily_unavailable`. Production keeps it on.
- Optional protocol features stay at their defaults, so JAR is off and discovery
  does not announce `request_parameter_supported`. A `request` parameter is then
  refused by OpenIddict while extracting the request, before the redirect URI has
  been validated, so the error is shown on the OP's own page instead of being
  sent to the client — see the entry for
  `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`
  in `config/expected-failures.json`.

## Browser automation

The suite drives a scripted browser, and the plan configuration says what each
page is for. Two details are easy to get wrong:

- The callback task must match the suite's own base URL. The authorization URL
  carries the callback inside its `redirect_uri` parameter, so a loose
  `*/test/*/callback*` pattern also matches the authorization page.
- Some modules ask for a screenshot: the second login page of
  `oidcc-prompt-login`, and the error pages of the modules listed under
  `override`. A `wait` command ending in `update-image-placeholder-optional`
  uploads one whenever the module is waiting for it.

## Expected failures

`config/expected-failures.json` and `config/expected-skips.json` use the suite's
own format. Every entry must say why the failure is accepted, and a finding that
reflects a real defect is fixed in the server instead of being listed.

## Seeder

`conformance/seeder` is deliberately outside `Sufficit.Identity.sln`: it is never
built into or shipped with the server. It composes the STS services with
`AddSufficitIdentitySTS` against the environment's database and uses the
OpenIddict and ASP.NET Core Identity managers, so the clients and the user are
created exactly as the server would store them.
