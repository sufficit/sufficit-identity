# Identity management and application authorization

## Decision

Sufficit Identity is a generic identity provider and authorization server. It
must not assign business meaning to role names such as `Administrator`,
`Manager`, reseller, department or tenant. Those names belong to a relying
party or to a deployment-specific business domain.

The provider may persist and emit custom claims requested by an authorized
client, but the generic runtime treats their type and value as opaque data. It
does not infer role inheritance, tenant reach or delegation rights from them.

This corrects the previous Management UI design, which incorrectly embedded the
Sufficit company's role and directive model in the identity provider.

## Standards boundary

| Concern | Owner | Standard or contract |
| --- | --- | --- |
| Authenticate an end-user | Identity provider | OpenID Connect Core |
| Issue and validate delegated access | Authorization server and resource server | OAuth 2.0 and its current security extensions |
| Publish identity claims | Identity provider | OIDC standard claims plus explicitly configured custom claims |
| Register OAuth/OIDC clients | Authorization server | OAuth/OIDC registration contracts |
| User and group provisioning interoperability | SCIM service provider | RFC 7643 and RFC 7644 |
| Decide what a role means inside an application | Relying party/resource server | Application policy |
| Compute Sufficit roles from directives and contexts | Sufficit applications | Sufficit business contracts |

OIDC permits additional claims beyond its standard claim set, but does not
standardize `Administrator` or `Manager` semantics. OAuth scopes describe
delegated access to protected resources; they are not an organizational role
hierarchy. SCIM defines interoperable `User` and `Group` resources and includes
attributes such as roles and entitlements, while leaving the authorization
effect of group membership to the service provider.

Primary references:

- [OpenID Connect Core 1.0, UserInfo and standard claims](https://openid.net/specs/openid-connect-core-1_0-18.html#UserInfo)
- [RFC 6749, OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 7643, SCIM core schema](https://www.rfc-editor.org/rfc/rfc7643)
- [RFC 7644, SCIM protocol](https://www.rfc-editor.org/rfc/rfc7644)

## Generic Identity responsibilities

The Management UI may administer provider-owned state:

- stable subject identifier;
- user name and profile claims;
- e-mail and phone verification state;
- credentials, passkeys and external logins;
- MFA enrollment and recovery;
- account activation or lockout;
- sessions, tokens, grants and consents;
- OAuth/OIDC clients, redirect URIs, scopes and protocol features;
- signing keys, branding and provider configuration;
- audit events produced by these operations.

User-management operations are global to the identity store unless the provider
implements a standards-based realm or organization feature as an explicit,
independent capability. A Sufficit `ContextId` is not such a feature and must
not filter the generic user directory.

Passwords, hashes, recovery material, client secrets and tokens are never
returned by list or detail operations.

### Named-secret namespaces

Named Vault secrets use an explicit provider-owned authorization tuple:
`(contextId, namespace, normalizedName)`. The first path segment is the
namespace; descendants inherit it and cannot declare a different owner or
context. The capability authorizes the operation and
`identity_vault_namespace` authorizes one exact `<contextId>:<namespace>` pair.
Contexts organize data; they are not a tenant boundary. Lists apply the same
predicate as get/put/delete.

`identity_vault_break_glass` is a separate MFA-bound claim issued outside the
generic Management APIs. Its use is always recorded in the Management audit
log. It may bypass a Vault namespace restriction.
The generic Claims API reserves all authorization-sensitive claim types,
including namespace, capability and break-glass types, so claim
administration cannot grant Management authority.

### No tenant boundary inside a deployment

One deployment serves one organization. There is no tenant concept in the
data model or in Management authorization: the former `identity:tenant`
authority, the `TenantAccess:SubjectTenants` mapping and
`ManagementResource.TenantId` were removed in August 2026, and object-level
authorization is capability, MFA and protected principals.

Isolation between organizations is a separate deployment. Starting another
application instance is cheap, and a process, database and key boundary is both
stronger and simpler than a row-level tenant filter that every query must
remember.

The 2026-09-12 evaluation (A10) recommended keeping a `TenantId` column on the
provider-owned tables anyway, for a future second customer. The maintainer
confirmed on 2026-09-14 that the August decision stands: a column that always
holds the same value is dead code that each change would have to maintain, and
a future shared deployment would need a deliberate realm design rather than a
retrofitted column. Do not reintroduce tenant data or authority without a new
decision recorded here.

## Relying-party responsibilities

An application owns:

- its business-role catalog and inheritance;
- permissions, directives and resource-level policies;
- tenant, reseller, customer or department membership;
- who may delegate each business authority;
- business-specific MFA or approval rules;
- the interpretation of custom role, group or entitlement claims.

For Sufficit, this model is visible in:

- `sufficit-identity-core`, which defines `AdministratorRole`, `ManagerRole`,
  application roles and directive types;
- `sufficit-blazor`, whose Identity feature edits user directives and displays
  computed roles;
- Sufficit API authorization, which combines those claims with the requested
  business resource and context.

The Sufficit application may call generic identity/SCIM management endpoints to
create an account, update profile data or disable authentication. It separately
updates its own business grants. These operations can share one workflow
without sharing one domain model.

## Management operator authorization

Authorization to operate the provider is separate from the authorities stored
on a target user.

Neste modelo, **operador** é apenas o administrador autenticado que executa uma
ação no Management. Não é um tipo de usuário, papel ou entidade persistida
separadamente. Para que esse termo interno não vaze para o contrato público, as
capabilities de administração de tokens usam o namespace `identity.tokens.*`.

### Naming rule

Every capability is `identity.<resource>.<action>` or
`identity.<resource>.<qualifier>`, optionally followed by one more level
(`identity.users.mfa.reset`). Every segment is **one lowercase word** — no
hyphens, no compound words — so every name matches
`^identity(\.[a-z]+){2,3}$` (pinned by `ManagementCapabilityNamingTests`).

The **`.system` qualifier** means "every action of that resource, but only on
system users" (users with nothing to sign in with, recognized by
`SystemUserStore.WhereSystemUser`):

- `identity.users.system` satisfies users read/create/disable/reset in the
  system-users API (`/api/users/system`) and nowhere else: every operation
  creates a system user or resolves its target among system users first.
- `identity.claims.system` satisfies claims read/create/update/delete on
  `/api/claims` only when the claim's owner is a system user. For any other
  owner it never does: the request is refused (`claim_owner_not_system_user`)
  and mutations are audited like other refusals. The general capability is
  tried first, so an operator holding both is unaffected. Reserved claim types
  and the protected-principal policy still apply.

The generic management application evaluates this catalog
(`ManagementCapabilities.All`):

| Resource | Capabilities |
| --- | --- |
| Clients | `identity.clients.read` `.create` `.update` `.delete` |
| Branding | `identity.branding.read` `identity.branding.manage` |
| Users | `identity.users.read` `.create` `.update` `.disable` `.delete` `.reset` `.confirmation` `.system`, `identity.users.mfa.reset` |
| Claims | `identity.claims.read` `.create` `.update` `.delete` `.system` |
| Scopes | `identity.scopes.read` `.create` `.update` `.delete` |
| Sessions | `identity.sessions.read` `identity.sessions.revoke` |
| Authorizations | `identity.authorizations.read` `identity.authorizations.revoke` |
| Audit | `identity.audit.read` |
| Database | `identity.database.read` |
| Maintenance | `identity.maintenance.read` `identity.maintenance.manage` |
| Proxies | `identity.proxies.read` `identity.proxies.manage` |
| Metrics | `identity.metrics.read` `identity.metrics.manage` |
| Secrets | `identity.secrets.read` `.manage` `.resolve` |
| Provisioning | `identity.provisioning.preview` `identity.provisioning.apply` |
| Tokens | `identity.tokens.read` `.issue` `.revoke` |

Delegated credentials (RFC 8693) are audited under the audit-only label
`identity.credentials.delegate`; it is not a grantable capability.

### Retired names

Retired spellings are accepted on input and normalized
(`ManagementCapabilities.Normalize` / `LegacyNames`) wherever a capability
enters: `permission` claims (including operator tokens already issued),
`RoleCapabilities`, `ServicePrincipals` roles, operator-token issuance and
listing, the service-account screen, query-string prefill and the evaluator
itself. They are not in the catalog and are never emitted in new tokens,
responses or generated configuration.

| Retired | Canonical |
| --- | --- |
| `identity.users.reset-password` | `identity.users.reset` |
| `identity.users.resend_confirmation` | `identity.users.confirmation` |
| `identity.users.reset-mfa` | `identity.users.mfa.reset` |
| `identity.system-users.manage` | `identity.users.system` |
| `identity.trusted-proxies.read` / `.manage` | `identity.proxies.read` / `.manage` |
| `identity.vault.secrets.read` / `.manage` / `.resolve` | `identity.secrets.read` / `.manage` / `.resolve` |
| `identity.management.tokens.read` / `.issue` / `.revoke` | `identity.tokens.read` / `.issue` / `.revoke` |
| `identity.operator-tokens.read` / `.issue` / `.revoke` | `identity.tokens.read` / `.issue` / `.revoke` |

For an HTTP Management API, an access token must carry the management transport
scope and the required operation capability. For the embedded UI, the host may
map one or more deployment-specific operator roles to the full provider
capability set. That mapping belongs to composition/configuration and is never
shown as a role recommendation for managed users.

The Sufficit deployment maps its company `administrator` role to full
provider operator access because that is a host choice. Its `manager` role maps
to `identity.users.read` and `identity.claims.read/create/delete` only — the
directive and entitlement claims managers keep for their company users — and
other deployment roles map to narrow sets (vault secrets, system users, claim
reads). The mapping lives in `Management:Authorization:RoleCapabilities`.

### Where operator authority comes from

Console authority never comes from something the console itself can hand out:

- **Roles** grant it only through the reviewed mapping above, and no Identity
  surface — Management, SCIM, provisioning — assigns roles
  (`OperatorAuthorityContractTests`).
- **Capability claims** (`permission`), the protected-principal tier and the
  break-glass markers are reserved: the claim API refuses them, and token
  release drops them whatever the unmapped-claims setting, so they never reach
  a relying party.
- **Operator tokens** delegate a subset of the issuing operator's own
  capabilities; issuing and revoking them is never delegable.
- **Service principals** get theirs from the closed `ServicePrincipals` list.

Break-glass against a protected principal is recorded the same way whichever
path reaches the user — the user itself, a claim, a session or an
authorization: `AuthorizationOutcome` reads
`allowed:protected_principal_break_glass` next to the operation's own reason
code.

## Management UI changes

The corrected UI:

- lists the global identity directory without tenant/context filters;
- does not show or mutate Sufficit roles or directives;
- does not offer `Administrator` or `Manager` as user-role choices;
- creates a provider identity without a Sufficit context;
- presents account, verification, MFA and lockout state;
- keeps password reset, profile update and session revocation as provider
  security operations;
- requires an exact user-name confirmation before permanent account deletion,
  blocks self-deletion and revokes sessions, tokens and authorizations first;
- removes the former generic `/management/access` information page;
- exposes Claims from each user detail as persisted custom-claim assignments,
  with per-account search, creation, editing and removal; the stable Claims
  routes receive `user` and `claim` through the query string rather than
  embedding identifiers in the path;
- exposes Scopes under OAuth/OIDC as custom OpenIddict definitions, with list,
  creation, detail, update and guarded deletion;
- exposes Authorizations under OAuth/OIDC as grants/consents with scopes and
  guarded revocation of the authorization and its related credentials;
- exposes Sessions under Operations as safe OpenIddict credential metadata,
  with individual revocation and account-wide invalidation;
- projects runtime environment, HTTP transport settings, MFA policy, effective
  capabilities and module availability through one shared overview contract;
- treats claims as opaque attributes and never suggests Sufficit business roles;
- protects protocol/profile claim types from manual override;
- rotates the target user's security stamp and revokes active tokens whenever a
  claim assignment changes;
- leaves manifest-managed scopes read-only and blocks scope deletion while a
  client still has permission to request it.

The claim contract deliberately has no built-in business catalog. Standard
claim names may be suggested by the presentation layer for usability, but the
application service accepts opaque custom types and values after enforcing its
reserved-claim boundary.

SCIM is a separate protocol adapter under `/scim/v2`. Its Users project the
same Identity accounts and its Groups use dedicated SCIM tables rather than
legacy `roles`/`userroles`. Management and SCIM share the neutral
`IIdentityAccountLifecycleService` for activation, revocation and deletion, so
transport does not create a second security implementation.

Claims use the existing ASP.NET Identity `userclaims` store; scopes, sessions
and authorizations use the existing OpenIddict `scopes`, `tokens` and
`authorizations` stores. These verticals therefore require no new database
table or migration. Token payloads and reference identifiers are deliberately
absent from management DTOs and audit events.

## Source-of-truth rule

The embedded UI and HTTP adapters execute the same application services. The UI
does not access `DbContext`, `UserManager`, `SignInManager` or OpenIddict
managers directly.

There is one implementation for each provider operation:

```text
Management UI ─┐
               ├──> identity application service ──> provider persistence
Management API ┘

Sufficit Blazor ──> identity/SCIM API ──> identity application service
        └────────> Sufficit business API ──> roles/directives/contexts
```

## Acceptance criteria

- No generic Management UI copy names Sufficit `Administrator` or `Manager`.
- The user list/detail contracts do not expose business roles or contexts.
- User creation does not require or persist a Sufficit `ContextId`.
- The generic management assembly does not reference directive claim formats.
- The embedded Sufficit host can explicitly map `administrator` to provider
  operator access without making that role part of the generic user model.
- A Sufficit `manager` cannot enter the provider Management UI by default.
- Existing company role/directive management remains in `sufficit-blazor`.
- Authentication state changes rotate/revoke the appropriate provider
  credentials and remain audited.
- Management and SCIM account deletion execute the same lifecycle service.
- SCIM Group membership never mutates ASP.NET Identity roles.
- Home, Settings, navigation and layout project the canonical runtime overview;
  they do not invent readiness or availability labels.
- Claims are contextual to a user; scopes, sessions and authorizations have
  independent routes, capabilities and navigation entries.
- Claims routes fail closed when their required `user` query context is absent.
- Manifest-managed scopes cannot be manually updated or deleted.
- Claim values are never copied into management audit events.
