# Repository architecture and consolidation decision

Status: **consolidation recommended; physical migration awaiting approval**

Inventory date: 2026-07-31

## Executive decision

Sufficit Identity has three top-level product modules:

1. the Identity runtime and APIs;
2. the public/account UI;
3. the administrative Management UI.

They are separate .NET projects and must remain separate assemblies with clear
dependency boundaries. They are not, however, independent applications: both
UIs are Razor Class Libraries loaded by the same composition host, run in the
same process and are published in the same artifact.

The recommended repository model is therefore a **single `sufficit-identity`
monorepo containing all three modules**. Repository consolidation must not
collapse the projects or allow UI code to access persistence. Modularity is
provided by project references, contracts and architecture tests, not by the
current repository boundary.

No physical move is authorized by this document. The existing two-repository
layout remains operational until the migration plan below is explicitly
approved.

## Current layout: two repositories, three product modules

The term "three projects" is useful at the product level, but the solution is
internally more granular. There are currently eight `.csproj` files across two
repositories.

| Product module | Current repository | Projects | Runtime |
| --- | --- | --- | --- |
| Identity runtime and APIs | `sufficit-identity` | `Core`, `STS`, `Management`, `Scim`, `Server`, `Tests` | `Server` is the only executable |
| Public and account UI | `sufficit-identity-ui` | `Sufficit.Identity.UI` | RCL embedded in `Server` |
| Administrative UI | `sufficit-identity-ui` | `Sufficit.Identity.UI.Management` | RCL embedded in `Server` under `/management` |

`Sufficit.Identity.Management` is the application/API module. It is not the
Management UI. `Sufficit.Identity.UI.Management` is only its presentation
adapter. Both embedded UIs reuse the authentication session and runtime of the
Identity host; neither owns a port, process, database connection or deployment.

```text
Sufficit.Identity.Server (only executable)
├── Sufficit.Identity.STS
├── Sufficit.Identity.Management      (application services + Management API)
├── Sufficit.Identity.Scim
├── Sufficit.Identity.Core
├── Sufficit.Identity.UI              (public/account RCL)
└── Sufficit.Identity.UI.Management   (administrative RCL)
```

## Why the current repository split is not independent

The source dependency is bidirectional at repository level:

- `Sufficit.Identity.Server` references both projects in
  `sufficit-identity-ui` through sibling relative `ProjectReference` paths;
- `Sufficit.Identity.UI` references `sufficit-identity/src/core`;
- `Sufficit.Identity.UI.Management` references
  `sufficit-identity/src/management`;
- the Identity CI checks out a pinned UI SHA;
- the UI CI checks out a pinned Identity SHA;
- the Docker build requires both repositories as separate BuildKit contexts;
- the integrated UI, routing and architecture tests live in
  `sufficit-identity/src/tests`;
- the deployed artifact always contains both repositories' assemblies.

Consequently, neither repository can restore, build, test or release its real
product graph by itself. A contract-plus-presentation change needs coordinated
commits and reciprocal SHA maintenance. The `IsPackable` flags on the RCLs do
not provide independence because no compatible UI package release is consumed
by the host and the RCLs themselves consume source projects from Identity.

## Decision matrix

| Criterion | Keep two repositories | Consolidate in `sufficit-identity` |
| --- | --- | --- |
| Atomic contract + UI change | Requires coordinated commits and pins | One commit |
| Reproducible build | Reciprocal SHA pins | One repository SHA |
| Local clone/build | Requires sibling layout | Works from one clone |
| Docker | Two build contexts | One build context |
| CI | Two partial pipelines plus cross-checkouts | One complete pipeline |
| Deployment | Always one artifact | One artifact |
| Assembly modularity | Yes | Yes, unchanged |
| Independent product release | Not present today | Can still publish selected projects later |
| History migration cost | None | One controlled import |

The only strong reason to keep the repositories separate would be a real,
independent package lifecycle with external consumers, semantic versions and a
compatibility policy. That lifecycle does not exist today. If it becomes useful
later, NuGet packages can be produced from the monorepo without moving their
source back out.

## Current functional state

### Identity runtime and APIs

Implemented:

- one composition host for STS, UIs, Management API and SCIM;
- OAuth/OIDC flows, Identity persistence and OpenIddict adapters;
- canonical application services shared by UI and HTTP adapters;
- Management API for clients, users, claims, scopes, sessions,
  authorizations, branding, audit, overview and provisioning;
- SCIM Users and Groups with a neutral account lifecycle;
- MariaDB migrations, security controls and 212 integrated tests.

Known work outside the repository move:

- complete protocol features that are explicitly disabled or unadvertised,
  including full front-channel logout and the remaining back-channel logout
  interoperability work;
- execute the separately controlled legacy cutover/migration gates;
- expand SCIM interoperability only when concrete integrations require it.

### Public and account UI

Implemented:

- login, consent, logout, device verification and external-provider surfaces;
- complete authenticated account management for profile, password, personal
  data, deletion, connected applications, active sessions, external
  identities, two-factor authentication and passkeys;
- shared runtime use cases for the authenticated account-management vertical;
- server-side passkey tickets and semantic passkey rename/removal.

Remaining architecture debt:

- password login, login 2FA, recovery-code login and logout still inject
  `SignInManager` directly;
- registration, email confirmation/resend and password recovery/reset still
  inject `UserManager` directly;
- consent still injects an OpenIddict application manager;
- the anonymous external-login controller still injects Identity managers;
- the UI repository has no independent test project; its effective tests are
  integrated with the Identity host.

These are migrations to shared application contracts, not missing account UI
screens.

### Management UI

The planned Management UI scope is implemented:

- overview and settings from the runtime contract;
- clients, users, per-user claims, scopes, sessions and authorizations;
- branding, audit and declarative provisioning;
- capability-based authorization and MFA policy projection;
- safe security mutations and persistent audit;
- responsive loading, error, empty and access-denied states.

The Management RCL has no direct `DbContext`, `UserManager`, `SignInManager` or
OpenIddict-manager dependency. Sufficit business roles, directives, tenants and
reseller contexts deliberately remain outside this generic provider console.

## Recommended target layout

```text
sufficit-identity/
├── src/
│   ├── core/
│   ├── sts/
│   ├── management/          # application services + Management API
│   ├── scim/
│   ├── ui/
│   │   ├── Sufficit.Identity.UI/
│   │   └── Sufficit.Identity.UI.Management/
│   ├── server/              # only executable composition host
│   └── tests/
├── docs/
├── helpers/
├── Dockerfile
└── Sufficit.Identity.sln
```

Assembly names, namespaces, static-web-asset paths, public routes and the
`/management` path base remain unchanged. Only source locations and build
orchestration change.

## Controlled consolidation plan

1. Approve a short freeze on changes to `sufficit-identity-ui`.
2. Import the UI repository history into `sufficit-identity` under `src/ui`
   using a filtered-history merge; do not squash or copy only the latest tree.
3. Add both RCL projects to `Sufficit.Identity.sln` and replace every sibling
   relative reference with an in-repository reference.
4. Reconcile central package/build settings while preserving both assembly
   names and all static asset identifiers.
5. Collapse CI into the Identity workflow; remove `UI_REF`, `IDENTITY_REF`,
   sibling checkouts and reciprocal pin comments.
6. Simplify Docker to one build context and remove the sibling-repository
   fallback/error targets.
7. Run warnings-as-errors, all 212+ tests, MariaDB migration checks,
   vulnerability audit, secret scanning and a published-artifact smoke test.
8. Deploy one release and verify public UI, account UI, Management UI, API,
   SCIM and health endpoints.
9. Keep `sufficit-identity-ui` intact for rollback until the consolidated
   release is accepted; then archive it read-only with a pointer to the new
   source location. Do not delete its history.

## Acceptance criteria for consolidation

- a fresh clone of `sufficit-identity` restores, builds, tests and publishes;
- all eight projects are present in the single solution;
- no source path references a sibling `sufficit-identity-ui` checkout;
- CI contains no reciprocal repository SHA pin;
- Docker uses one source context;
- UI assemblies, routes and static asset URLs remain compatible;
- the UI projects still cannot access persistence or protocol managers except
  through the explicitly tracked public-UI migration debt;
- one commit can atomically change an application contract, both adapters and
  their tests;
- the deployed runtime remains one process and one artifact.

## Safe workflow while the repositories remain separate

Until consolidation is approved and completed:

1. Treat `sufficit-identity` as the composition and release repository.
2. Treat both projects inside `sufficit-identity-ui` as embedded RCLs, never as
   standalone applications.
3. For an Identity contract change, commit Identity first and update the
   UI workflow's pinned `IDENTITY_REF` before validating the UI.
4. Commit the compatible UI change, then update Identity's pinned `UI_REF`.
5. Require both CIs to pass and publish only from the final compatible pair.
6. Record both SHAs in the release name or deployment record.

This workflow is deliberately more expensive than the target monorepo flow;
it exists only to keep the current split deterministic during the transition.

## Next implementation work

The repository decision should be closed before another cross-repository
vertical is started. After consolidation, the next product work is to migrate
the remaining public authentication flows to neutral application contracts, in
this order:

1. password login, login 2FA, recovery code and logout;
2. registration, email confirmation/resend and password reset;
3. consent and anonymous external login;
4. architecture tests that reject new direct UI dependencies.
