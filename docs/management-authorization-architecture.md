# Management authorization architecture

> Status: host integration, global client/branding capabilities, persistent
> audit, normalized grants, Sufficit directive resolution, per-context MFA
> policy and contextual user read contracts implemented. Contextual creation
> password reset, lockout and unlock follow the multi-context rule recorded
> below. Lockout also invalidates the Identity session and revokes the target
> subject's OpenIddict tokens and authorizations.
> Authorization is decided by the shared application layer used by the UI and
> Management API. The canonical boundary is
> [`single-source-ui-architecture.md`](single-source-ui-architecture.md).

## Goal

Provide a reusable authorization model for an OpenIddict/ASP.NET Core Identity
management product while preserving first-class compatibility with the
Sufficit roles, directives and context model.

The generic management modules must not reference Sufficit-specific role
classes, directive classes, GUIDs or claim formats. Sufficit behavior is added
through a replaceable adapter at the composition boundary.

## Confirmed product decisions

- OAuth/OIDC clients and global identity-service configuration are managed only
  by an `Administrator`.
- Users are managed by a `Manager` within the contexts granted to that
  operator.
- In the Sufficit host, `Administrator` explicitly inherits every `Manager`
  capability with global scope and adds the administrator-only capabilities.
- A manager's effective authority is computed from roles and directives; a
  manager role alone must not silently widen a context-bound grant.
- MFA is configurable per tenant for context-bound operations.
- The first vertical delivery is host-session integration, authorization,
  auditing and OAuth clients: list, detail, create and delete.
- User administration follows in the next vertical delivery.
- OAuth clients are global resources in the first delivery and are not assigned
  to tenants.
- Todas as UIs consomem dados, capabilities e comandos pelos mesmos use cases
  usados pela API; HTTP é um adaptador, não uma segunda implementação.
- Uma conta nova recebe associação explícita ao contexto, sem receber papel ou
  diretiva de autoridade implicitamente. Diretivas continuam sendo a fonte das
  capabilities do operador.
- Uma mutação global de credencial em conta multicontexto só pode ser executada
  por um `Manager` que possua a capability exigida em todos os contextos da
  conta. Qualquer contexto fora de sua autoridade, associação global ou conta
  sem contexto exige `Administrator`. Diretiva global, malformada ou sem
  contexto resolvível também falha fechada e exige `Administrator`.
- Bloqueio e desbloqueio são mutações sobre a conta inteira e seguem a mesma
  validação de todos os contextos. Bloquear atualiza o security stamp e revoga
  tokens e autorizações; desbloquear não restaura nenhuma sessão anterior.
- Um operador não pode bloquear a própria conta pela Management UI/API.

## Existing Sufficit model

The current `sufficit-endpoints` flow provides useful compatibility behavior:

1. After token validation, the API replaces the raw principal with a
   `SufficitWebUser`.
2. `UserPrincipal` parses each `directive` claim.
3. Each recognized directive may reference an `IDRole`; those references
   produce the effective, computed role set.
4. A directive carries a `ContextId`. Checks accept either the requested
   context or `Guid.Empty`, which is the Sufficit convention for all contexts.
5. Endpoint code combines role checks with `HasPolicy<T>(contextId)` or
   `ThrowIfUnauthorized<T>(contextId)`.

The model correctly treats directives as contextual grants and can derive
roles from those grants. The new implementation should preserve that outcome,
but not copy these implementation details into the generic core.

### Behaviors not to copy directly

- `IsManager()` currently acts as a global bypass for both managers and
  administrators in several endpoints. Global administrator access is
  intentional, but manager access must remain contextual.
- A directive filter can establish that the operator has a directive in some
  context without proving access to the resource being changed.
- Resource checks are repeated manually inside controllers.
- `Guid.Empty` is a Sufficit-specific wildcard.
- Reflection-based discovery of role and directive classes couples policy
  evaluation to a particular domain assembly.

## Authorization model

Authorization has three independent dimensions:

1. **Role** describes the operator's organizational function.
2. **Capability** describes the operation the operator may perform.
3. **Resource scope** describes where that capability applies.

A normalized grant is conceptually:

```text
capability: identity.users.reset-password
resource type: tenant
resource id: 4c3c...
source: directive/clientadmin:4c3c...
```

The core recognizes global and resource-bound scopes. It treats resource
identifiers as opaque strings; the Sufficit adapter may use `ContextId` GUIDs,
while another host may use organization slugs, numeric account IDs or an
external policy identifier.

### Initial capabilities

```text
identity.clients.read
identity.clients.create
identity.clients.delete

identity.users.read
identity.users.create
identity.users.update
identity.users.disable
identity.users.delete
identity.users.reset-password
identity.users.permissions.manage

identity.audit.read
identity.branding.manage
identity.provisioning.manage
identity.scopes.manage
identity.sessions.read
identity.sessions.revoke
```

Capabilities are stable contract identifiers. UI labels, role names and
directive names may change without changing those identifiers.

## Generic extension points

The management module should expose abstractions equivalent to:

```text
IManagementEntitlementResolver
    ClaimsPrincipal -> normalized grants

IManagementAuthorizationEvaluator
    operator + capability + resource -> authorization decision

IManagementAccessPolicyProvider
    global or resource scope -> MFA and other access requirements
```

An authorization decision is not only a boolean. It distinguishes:

```text
allowed
denied
step-up-required
```

It also carries a stable reason code suitable for `ProblemDetails`, telemetry
and audit records. It never exposes tokens, secrets or the full raw claim set.

The default implementation supports configurable claim and role names. Hosts
can replace the entitlement resolver without replacing the Management API.
ASP.NET Core policies and resource-based authorization handlers enforce the
decision.

## Sufficit adapter

The optional Sufficit adapter:

- reads explicit role claims;
- reads scalar and JSON-array `directive` claims;
- parses the existing `key:ContextId` format;
- resolves known directives through the Sufficit directive catalog;
- computes roles from each directive's `IDRole`;
- maps role/directive combinations to management capabilities;
- converts `Guid.Empty` to a global resource scope only inside the adapter;
- maps `Administrator` to every manager capability with global scope, in
  addition to administrator-only capabilities;
- fails closed for malformed or unknown grants;
- never makes a Sufficit type part of a generic API DTO.

For the first delivery, the essential mapping is:

```text
Administrator
    -> identity.clients.read      (global)
    -> identity.clients.create    (global)
    -> identity.clients.delete    (global)
    -> identity.users.*           (global, inherited from Manager)
    -> identity.audit.read        (global, subject to the audit policy)
```

The user-management read delivery maps explicit Manager roles to the non-empty
`ContextId` values carried by their valid Sufficit directive claims. A
`Guid.Empty` directive never promotes a Manager to global access.

## Authorization matrix

| Operation | Capability | Administrator | Manager |
|---|---|---:|---:|
| List and inspect OAuth clients | `identity.clients.read` | Global | Denied |
| Create OAuth clients | `identity.clients.create` | Global | Denied |
| Delete OAuth clients | `identity.clients.delete` | Global | Denied |
| Manage global scopes/branding/provisioning | specific global capability | Global | Denied |
| Search and view users | `identity.users.read` | Global | Granted contexts |
| Create and update users | `identity.users.create` / `identity.users.update` | Global | Granted contexts |
| Disable or delete users | `identity.users.disable` / `identity.users.delete` | Global | Granted contexts |
| Reset passwords | `identity.users.reset-password` | Global | Granted contexts |
| Change roles, claims and directives | `identity.users.permissions.manage` | Global | Granted contexts plus delegation limits |
| Read audit events | `identity.audit.read` | Global when granted | Granted contexts when granted |

This inheritance is an explicit Sufficit adapter rule. The generic core does
not assume that every host treats `Administrator` as a superset of `Manager`.

Password reset is a single account-wide mutation, even when the account belongs
to several contexts. The application service therefore resolves the target
membership from persistence and evaluates `identity.users.reset-password`
against every context before touching the credential. A context supplied by
the browser is never accepted as proof of the account's complete scope.

Lockout and unlock use the same account-wide authorization rule with
`identity.users.disable`. The application service changes the ASP.NET Identity
lockout state, rotates the security stamp and revokes every OpenIddict token and
authorization associated with the subject. The Identity cookie stamp is checked
on every authenticated request, so local sessions are invalidated on their next
request. Reference tokens and refresh tokens are rejected from their persisted
entry immediately; deployments that issue self-contained JWT access tokens must
also use introspection/token-entry validation or accept their configured short
lifetime as the revocation bound.

User creation is contextual and least-privileged. The initial context
association is stored separately from authority directives, so creating an
identity cannot accidentally delegate a role or capability. The Sufficit
adapter reads this explicit association alongside legacy directive-derived
membership; existing accounts remain compatible without a data migration.

## Enforcement flow

Every external Management API request follows this order:

1. Authenticate the operator and validate the intended token audience.
2. Require the Management API OAuth scope.
3. Resolve normalized grants from the principal.
4. Resolve the actual target resource and its tenant/context.
5. Evaluate the requested capability against that resource.
6. Apply global or tenant access policy, including MFA.
7. Execute the operation only after authorization succeeds.
8. Record the authorization decision and operation result in the audit trail.

For collections, tenant constraints are applied to the data query. The API
must not load a cross-tenant result set and filter it afterward.

For detail, update and delete operations, the API loads the resource identity
and tenant before resource-based authorization. A tenant identifier supplied
only in a request body is never trusted as proof of ownership.

UI capability checks improve navigation and explanations, but never replace
API authorization.

The embedded UI uses the shared application boundary:

1. Authenticate with the ASP.NET Identity application cookie already issued by
   the composition host.
2. Resolve the same application contract used by the Management API.
3. Resolve operator capabilities, resource scope and MFA policy in that use
   case.
4. Apply resource/capability authorization in the application layer.
5. Audit every mutation before returning its result.

The embedded UI does not need an HTTP self-call and must not register a
self-referential OIDC client. External automation reaches the API controller
with bearer authentication; the controller delegates to the same use case.

## MFA policy

`IManagementAccessPolicyProvider` keeps MFA policy storage outside the generic
authorization engine.

- Global administrative operations use a global policy.
- User operations use the policy resolved for the target tenant.
- A host may back the provider with configuration, a local database or an
  external tenant service.
- When MFA is required, the access token must contain trustworthy `amr`
  evidence.
- Missing evidence returns `step-up-required`; it is not presented as a generic
  forbidden response.

The composition host is responsible for step-up authentication. The embedded
UI reuses its HttpOnly Identity session and does not own access or refresh
tokens. A future tenant policy may challenge the operator to complete MFA and
then return to the original Management route.

## Audit contract

Audit records include:

- operator subject and display identifier;
- requested capability;
- resource type and identifier;
- tenant/context identifier when applicable;
- authorization outcome and stable reason code;
- operation outcome and HTTP status;
- UTC timestamp and correlation ID;
- authentication method evidence needed for compliance decisions.

Client secrets, passwords, reset tokens, access tokens, refresh tokens and raw
authorization headers are always redacted.

## Delivery phases

### Phase 1 — Contracts and security foundation

- Define capability, resource, grant and decision contracts.
- Implement default-deny authorization handlers.
- Add configurable generic entitlement and access-policy providers.
- Add the Sufficit adapter at the composition boundary.
- Version the Management API DTOs and OpenAPI contract.
- Test generic behavior independently from Sufficit types.

### Phase 2 — Embedded host integration

- Package the Management UI as a Razor Class Library.
- Map it under a configurable non-root path in the identity composition host.
- Reuse the host ASP.NET Identity cookie.
- Add separate module-access and client-administration policies.
- Consume versioned application contracts shared with the Management API.
- Implement login challenge, access denied and future step-up outcomes without
  a self-referential OIDC client.

### Phase 3 — Audit foundation

- Persist append-only administrative events.
- Audit authorization decisions and mutation results.
- Expose paginated audit list and detail contracts.
- Apply secret redaction and correlation IDs.

### Phase 4 — OAuth clients vertical slice

- Require global administrator capabilities.
- List and search clients.
- Show client details.
- Create clients with secure defaults.
- Delete clients with explicit confirmation.
- Cover UI -> application service and API controller -> the same application
  service with integration tests.

### Phase 5 — Contextual user administration

- Add paginated user contracts. **Concluído para acesso, lista e detalhe.**
- Resolve each user's tenant/context before authorization. **Concluído para
  claims Sufficit `directive`.**
- Add manager capabilities derived from Sufficit directives. **Concluído para
  `identity.users.read`; Manager never receives global bypass.**
- Apply per-tenant MFA policy. **Contrato e configuração concluídos; provider
  externo continua substituível.**
- Criar usuários com associação explícita a um contexto autorizado, sem papel
  ou diretiva implícita. **Concluído.**
- Redefinir senha somente após validar todos os contextos persistidos da conta.
  **Concluído, incluindo MFA por contexto e escalonamento para Administrator.**
- Bloquear/desbloquear a conta após validar todos os contextos, revogar
  sessões/tokens/autorizações e impedir autobloqueio. **Concluído, incluindo
  auditoria por contexto e MFA por tenant.**
- Add delegation limits for roles, claims and directives.
- Audit all read and mutation paths. **Leituras, criação, reset de senha e
  bloqueio/desbloqueio concluídos.**

### Phase 6 — Remaining modules

- scopes;
- sessions and grants;
- branding;
- provisioning;
- broader operational audit views.

## First-delivery acceptance criteria

- Anonymous access is challenged by the host Identity cookie handler.
- The Management UI does not require its own OIDC client, port or process.
- Administrative access/refresh tokens never become accessible to browser
  JavaScript because the embedded flow does not mint them for the UI.
- A token with the API scope but without `Administrator` is denied client
  operations.
- A `Manager` without administrator capability is denied client operations.
- An `Administrator` with the correct scope can list, inspect, create and
  delete clients.
- Every mutation records operator, target, decision, outcome and correlation
  ID without storing a secret.
- `401`, `403`, step-up, expiry and API unavailability have different
  contracts and UI states.
- Antiforgery protects interactive mutations.
- Integration tests exercise cookie-authenticated UI -> application service and
  bearer client -> API controller -> the same service.
- The generic authorization tests run without referencing Sufficit role or
  directive assemblies.
- Sufficit adapter tests cover scalar directives, JSON arrays, context scope,
  wildcard scope, malformed values and unknown directives.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Global manager bypass leaks cross-tenant data | Only Administrator receives the explicit global inheritance; Manager remains contextual |
| Attribute proves a directive in the wrong tenant | Authorize against the resolved resource |
| Collection leaks records from other tenants | Push authorized scopes into the database query |
| Stale role/directive claims preserve removed access | Short token lifetime, refresh/revalidation policy and revocation strategy |
| Self-contained JWT remains valid after account lockout | Prefer reference/introspected tokens or enable token-entry validation at resource servers; otherwise bound exposure with a short access-token lifetime |
| Production omits required role/directive scopes | Validate discovery and client permissions before rollout |
| UI hides an action but another transport still accepts it | Each transport has a policy and the application layer gains resource-capability enforcement |
| UI bypasses the application layer | Architecture tests reject direct UI references to persistence and Identity/OpenIddict managers |
| Unknown adapter data expands access | Fail closed and audit the denial reason |
| MFA policy store is unavailable | Fail closed for operations whose policy cannot be resolved |
| Audit captures secrets | Central redaction with security tests |
| Generic core drifts toward Sufficit conventions | Contract tests with a second, non-Sufficit entitlement resolver |

## Open decisions

1. Qual backend substituirá a configuração local como fonte das políticas MFA
   por tenant no host Sufficit?
2. Which user capabilities may a manager delegate to another operator?
3. What are the audit retention and export requirements?

## Current implementation evidence

- The Management UI is an injectable Razor Class Library mapped at
  `/management` by `Sufficit.Identity.Server`.
- It reuses the host Identity cookie; no OIDC/BFF client or token propagation
  is required.
- Module access accepts configured Administrator/Manager roles. Client and
  branding operations require global Administrator grants; user reads accept
  Administrator globally or Manager only in resolved contexts.
- The real client list correctly uses `IClientManagementService` through a
  short DI scope, and the REST controller uses the same service.
- Client and branding controllers are thin adapters over their shared
  application services.
- The Management API gates transport by authentication/scope and every
  delivered application service evaluates operator capability and resource.
- The API exposes client, branding and provisioning operations.
- User access, paginated list, detail, contextual creation and password-reset
  contracts exist. Account lockout/unlock also exists with security-stamp
  rotation and OpenIddict token/authorization revocation. Profile update,
  delete, role/claim delegation, independent scope and session/grant contracts
  do not.
