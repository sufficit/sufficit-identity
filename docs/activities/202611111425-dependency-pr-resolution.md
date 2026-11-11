# Dependency PR resolution

## Changes

Integrated the original heads of PRs [#110](https://github.com/sufficit/sufficit-identity/pull/110), [#111](https://github.com/sufficit/sufficit-identity/pull/111), [#112](https://github.com/sufficit/sufficit-identity/pull/112), [#113](https://github.com/sufficit/sufficit-identity/pull/113), [#114](https://github.com/sufficit/sufficit-identity/pull/114) and [#115](https://github.com/sufficit/sufficit-identity/pull/115) locally before publishing the corrected combination to main.

- Aligned CodeQL init/analyze at `33d7b85da1a04171e211befe2c739303b9a4c066` (4.39.3). Added a Dependabot group for `github/codeql-action/*` to prevent split upgrades.
- Upgraded OpenIddict to 7.8.0 and resolved its ObjectPool NU1107 conflict by pinning Microsoft.Extensions.ObjectPool 10.0.14 with a direct reference in the shared test project, inherited by BrowserTests.
- Integrated GitHub OAuth 10.1.0, bunit 2.14.0 and Markdig 1.6.0.
- Regenerated locks in package mode, including the existing UI locks that referenced the sibling project. No product-specific authorization semantics changed.

## Validation

- Reproduced NU1107 before the ObjectPool correction.
- `dotnet restore Sufficit.Identity.sln --locked-mode -p:SufficitUseLocalSui=false`: passed.
- `dotnet build Sufficit.Identity.sln --configuration Release --no-restore -warnaserror -p:SufficitUseLocalSui=false`: passed, no warnings/errors.
- Shared xUnit suite excluding BrowserHost: 2,150 executed and passed. Additional environment-gated cases were not executed.
- BrowserHost: all six passed, with required scripts and Playwright 1.61.1 enabled against isolated loopback hosts.
- MariaDbIntegration: six executed and passed on an ephemeral MariaDB 10.4.34 with canonical/additive SQL. Optional historical-host cases were not enabled. Container removed afterward.
- MFA authorization browser chain: both verified/unverified passkey cases passed.
- `python3 -I scripts/test_propagate_lock_versions.py`: all four passed.
- NuGet vulnerability audit including transitive dependencies: no advisories across 16 reported projects.
- Approved Pomelo artifact SHA-256 checks: passed.
- CodeQL init/analyze SHA consistency and Dependabot grouping inspected; `git diff --check`: passed.
- Full `docker build --file Dockerfile --tag sufficit-identity:pr-validation .`: passed, image `fbc91d7b5d4b`.

All local .NET commands that may restore must select package mode using `SufficitUseLocalSui=false` in this workspace. An intermediate audit without that setting rewrote UI locks for the sibling checkout and caused Docker NU1004; package-mode regeneration and the subsequent full Docker build passed.

Local TRX evidence: `/tmp/identity-pr-validation/`. Remote CI is separate from these local checks. Integration does not establish deployment or production behavior.

## Delivery

Published to main in `eae4f3267ab4f552df1be2949d569fb0870277ba`, after the six original merge commits. Individual GitHub PR reads confirmed all six `merged=true`, `state=closed`; the repository pull-request API returned no open PRs. GitHub [CI](https://github.com/sufficit/sufficit-identity/actions/runs/43067463037) and [CodeQL](https://github.com/sufficit/sufficit-identity/actions/runs/43067463039) started after push; their completion is not asserted here.
