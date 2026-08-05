# Repository architecture and consolidation record

Status: **consolidated, validated and deployed on 2026-08-01**

## Executive decision

Sufficit Identity has three top-level product modules:

1. the Identity runtime and APIs;
2. the public/account UI;
3. the administrative Management UI.

They remain separate .NET projects and assemblies with explicit dependency
boundaries. They are not independent applications: both UIs are Razor Class
Libraries loaded by the same composition host, run in the same process and are
published in the same artifact.

All source now lives in the `sufficit-identity` monorepo. Consolidation removed
the reciprocal repository dependency without collapsing the projects or
allowing presentation code to access persistence. Modularity is enforced by
project references, application contracts and architecture tests.

## Current monorepo layout

There are ten `.csproj` files in one solution:

| Product module | Source | Projects | Runtime |
| --- | --- | --- | --- |
| Neutral application contracts | `src/application/Sufficit.Identity.Application.Abstractions` | `Application.Abstractions` | Packable library with no project dependencies |
| Neutral UI hosting contracts | `src/ui/Sufficit.Identity.UI.Abstractions` | `UI.Abstractions` | Packable library with no runtime or UI implementation dependency |
| Identity runtime and APIs | `src/core`, `src/sts`, `src/management`, `src/scim`, `src/server`, `src/tests` | `Core`, `STS`, `Management`, `Scim`, `Server`, `Tests` | `Server` is the only executable |
| Public and account UI | `src/ui/Sufficit.Identity.UI` | `Sufficit.Identity.UI` | RCL embedded in `Server` |
| Administrative UI | `src/ui/Sufficit.Identity.UI.Management` | `Sufficit.Identity.UI.Management` | RCL embedded in `Server` under `/management` |

`Sufficit.Identity.Management` is the application/API module. It is not the
Management UI. `Sufficit.Identity.UI.Management` is its presentation adapter.
Both embedded UIs reuse the authentication session and runtime of the Identity
host; neither owns a port, process, database connection or deployment.

```text
Sufficit.Identity.Server (only executable)
├── Sufficit.Identity.Application.Abstractions
├── Sufficit.Identity.UI.Abstractions
├── Sufficit.Identity.STS
├── Sufficit.Identity.Management      (application services + Management API)
├── Sufficit.Identity.Scim
├── Sufficit.Identity.Core
├── Sufficit.Identity.UI              (public/account RCL)
└── Sufficit.Identity.UI.Management   (administrative RCL)
```

## Dependency rule and single source of truth

The UIs and HTTP controllers invoke the same application services. HTTP is a
transport option, not a required internal hop. Presentation projects must not
open database connections, resolve a `DbContext`, duplicate domain rules or
directly own Identity/OpenIddict persistence managers.

The intended dependency direction is:

```text
Public UI ─────────┐
Management UI ─────┼──> Application.Abstractions <── runtime adapters
HTTP APIs ─────────┘                                 Identity/OpenIddict/EF
```

Both UI project files reference only
`Sufficit.Identity.Application.Abstractions` plus presentation-framework
primitives. The abstraction project has no project-to-project references. The
composition host selects and registers runtime implementations before it adds
an embedded UI; a third-party UI receives no database or protocol-manager
access merely by being installed.

OpenIddict and ASP.NET Core Identity are current runtime adapters. New
application-facing contracts must remain neutral enough to replace those
adapters in the future. Their replacement is an architectural provision, not
part of the current implementation phase.

## Why consolidation was selected

The former split had a bidirectional repository dependency: the Server
referenced both UI projects, each UI referenced an Identity application
project, both CIs checked out reciprocal pinned SHAs, Docker required two build
contexts, and the deployed artifact always contained both repositories.

| Criterion | Former split | Current monorepo |
| --- | --- | --- |
| Atomic contract + UI change | Coordinated commits and pins | One commit |
| Reproducible build | Reciprocal SHA pins | One repository SHA |
| Local clone/build | Required sibling layout | Works from one clone |
| Docker | Two source contexts | One source context |
| CI | Two partial cross-checkouts | One complete pipeline |
| Deployment | One artifact assembled from two repos | One artifact from one repo |
| Assembly modularity | Separate projects | Separate projects, unchanged |

If independent package lifecycles become useful later, NuGet packages can be
published from this monorepo without moving source back out.

## Migration record

- Identity rollback point before import: `c117eaeebc7b07b323da64685d3add3a6c7d4763`.
- UI rollback point before import: `96dc4e81344a662422b9dab59f0ba9613adc4278`.
- The complete UI history was imported under `src/ui` by merge commit
  `adb1325`; it was not squashed.
- Both RCLs were added to `Sufficit.Identity.sln` without changing assembly
  names, namespaces, routes or static-web-asset identities.
- Central package versions and build settings now come from the repository
  root.
- Server references, tests, CI and Docker use only in-repository paths.
- CI run `30717538379` passed secret scanning, warnings-as-errors build,
  canonical MariaDB migration validation, 227 tests and dependency audit.
- Commit `c0218c07a7bdc904bd85b08c55d106142ba14b69` was deployed on
  `test-environment` as release
  `20260801T204513Z-c0218c0-runtime-boundary`; health, readiness, OIDC discovery,
  public UI, Management UI and both static-asset surfaces returned HTTP 200.
- The former UI repository remains a remote rollback/history source. Commit
  `5123fbabc3aa90d53492d3ec16cce11be8b44d6e` marks it legacy and links to the
  canonical monorepo. Its clean local checkout was removed on 2026-08-01 after
  confirming that both UI projects and imported history are present here.

## Functional state

Implemented runtime surfaces include OAuth/OIDC flows, ASP.NET Core Identity,
Management API, SCIM, public/account UI, Management UI, MariaDB migrations and
integrated architecture/routing/protocol tests.

The public/account UI covers login, consent, logout, device verification,
profile, password, personal data, deletion, connected applications, sessions,
external identities, two-factor authentication and passkeys.

The Management UI covers overview, settings, clients, users, per-user claims,
scopes, sessions, authorizations, branding, audit and declarative provisioning.
Sufficit business roles, directives, tenants and reseller contexts deliberately
remain outside this generic identity-provider console.

Known work independent of the repository move:

- complete protocol features that remain explicitly disabled or unadvertised,
  including remaining logout interoperability work;
- expand SCIM interoperability only for concrete integration requirements;
- execute the separately controlled legacy cutover/migration gates.

## Acceptance criteria

- [x] a fresh clone restores, builds, tests and publishes;
- [x] all ten projects are present in the single solution;
- [x] source references no sibling UI checkout;
- [x] CI contains no reciprocal repository SHA pin;
- [x] Docker uses one source context;
- [x] UI assemblies, routes and static asset identities remain unchanged;
- [x] UI projects remain presentation adapters without persistence ownership;
- [x] one commit can atomically change contracts, adapters and tests;
- [x] the consolidated CI passes on `main`;
- [x] the deployed runtime is verified as one healthy process and artifact;
- [x] the former UI repository is marked legacy with a canonical-source link.

This checklist is updated when each operational gate actually completes.

## Development workflow

Clone only `sufficit-identity`, then use the root solution:

```sh
dotnet restore Sufficit.Identity.sln
dotnet build Sufficit.Identity.sln --configuration Release
dotnet test Sufficit.Identity.sln --configuration Release --no-build
dotnet run --project src/server/Sufficit.Identity.Server.csproj
```

Changes that span an application contract and either UI belong in one commit
whenever practical. Runtime behavior must have tests in `src/tests`; UI-only
presentation detail remains inside the corresponding RCL.

## Next implementation work

The neutral application-contract extraction is complete. Public/account and
Management contracts now compile in
`Sufficit.Identity.Application.Abstractions`; both official UIs depend on that
assembly instead of `Core`, `STS` or `Management`. Architecture tests enforce
the dependency direction.

The next pluggable-UI milestone is explicit embedded composition: versioned
module descriptors, semantic endpoints and an official composition executable.
Remote Management BFF and remote public interactions remain later phases; this
work does not start the planned future replacement of OpenIddict.
