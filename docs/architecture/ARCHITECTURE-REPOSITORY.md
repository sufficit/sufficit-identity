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

There are eight `.csproj` files in one solution:

| Product module | Source | Projects | Runtime |
| --- | --- | --- | --- |
| Identity runtime and APIs | `src/core`, `src/sts`, `src/management`, `src/scim`, `src/server`, `src/tests` | `Core`, `STS`, `Management`, `Scim`, `Server`, `Tests` | `Server` is the only executable |
| Public and account UI | `src/ui/Sufficit.Identity.UI` | `Sufficit.Identity.UI` | RCL embedded in `Server` |
| Administrative UI | `src/ui/Sufficit.Identity.UI.Management` | `Sufficit.Identity.UI.Management` | RCL embedded in `Server` under `/management` |

`Sufficit.Identity.Management` is the application/API module. It is not the
Management UI. `Sufficit.Identity.UI.Management` is its presentation adapter.
Both embedded UIs reuse the authentication session and runtime of the Identity
host; neither owns a port, process, database connection or deployment.

```text
Sufficit.Identity.Server (only executable)
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
Management UI ─────┼──> application contracts/use cases ──> runtime adapters
HTTP APIs ─────────┘
```

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
  `castrum-apps` as release
  `20260801T204513Z-c0218c0-runtime-boundary`; health, readiness, OIDC discovery,
  public UI, Management UI and both static-asset surfaces returned HTTP 200.
- The former UI repository remains a rollback/history source. Commit
  `5123fbabc3aa90d53492d3ec16cce11be8b44d6e` marks it legacy and links to the
  canonical monorepo source without deleting its code or history.

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
- [x] all eight projects are present in the single solution;
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

The public authentication contract migration is complete:

1. password login, login 2FA, recovery code and logout — completed on
   2026-08-01 through `IInteractiveSignInService`;
2. registration, email confirmation/resend and password reset — completed on
   2026-08-01 through `IAccountOnboardingService`;
3. consent and anonymous external login — completed on 2026-08-01 through
   `IAuthorizationConsentService` and `IExternalSignInService`;
4. architecture tests now reject every direct Identity, EF Core or protocol
   implementation dependency in either UI, without a legacy exception list.

Further work is protocol interoperability, concrete SCIM integration demand and
the separately controlled legacy cutover, not presentation-layer decoupling.
