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
context. The capability authorizes the operation, the Management tenant
authority (`identity:tenant`) authorizes the tenant, and
`identity_vault_namespace` authorizes
one exact `<contextId>:<namespace>` pair. Lists apply the same predicate as
get/put/delete.

`identity_vault_break_glass` is a separate MFA-bound claim issued outside the
generic Management APIs. Its use is always recorded in the Management audit
log. It may bypass a Vault namespace restriction, but never tenant membership.
The generic Claims API reserves all authorization-sensitive claim types,
including tenant, namespace, capability and break-glass types, so claim
administration cannot grant Management authority.

### Management tenant boundary

Management tenant membership is represented by the private claim
`identity:tenant`. The claim is not a business role, an OAuth scope or a value
accepted from the browser. Before authorization, the host discards incoming
tenant claims and reconstructs them from the deployment-controlled mapping
`Management:Authorization:TenantAccess:SubjectTenants`, keyed by the stable
operator `sub`.

The mapping is stored in the root-controlled hardening configuration. A role
such as `administrator` can grant provider capabilities only after the same
subject has at least one explicit tenant assignment. An empty or malformed
mapping is a production-posture failure; there is no role-to-`global`
compatibility fallback.

Provider-wide objects whose model has no narrower tenant belong to
`ProviderTenantId` (currently `global`). This value identifies the resource;
it never grants membership. The operator still needs an explicit
`subject -> global` assignment. Deployments that introduce tenant-owned
objects must populate `ManagementResource.TenantId` and enforce exact ordinal
matching. The generic user directory remains provider-owned unless a separate
realm/organization feature is deliberately designed.

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

The generic management application evaluates stable capabilities such as:

- `identity.clients.read`
- `identity.clients.create`
- `identity.clients.delete`
- `identity.claims.read`
- `identity.claims.create`
- `identity.claims.update`
- `identity.claims.delete`
- `identity.scopes.read`
- `identity.scopes.create`
- `identity.scopes.update`
- `identity.scopes.delete`
- `identity.sessions.read`
- `identity.sessions.revoke`
- `identity.authorizations.read`
- `identity.authorizations.revoke`
- `identity.users.read`
- `identity.users.create`
- `identity.users.update`
- `identity.users.disable`
- `identity.users.delete`
- `identity.users.reset-password`
- `identity.audit.read`

For an HTTP Management API, an access token must carry the management transport
scope and the required operation capability. For the embedded UI, the host may
map one or more deployment-specific operator roles to the full provider
capability set. That mapping belongs to composition/configuration and is never
shown as a role recommendation for managed users.

The Sufficit deployment may map its company `administrator` role to provider
operator access because that is a host choice. Its `manager` role does not gain
access to the provider console; managers continue to manage company users and
directives through `sufficit-blazor`.

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
