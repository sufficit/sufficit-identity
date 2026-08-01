# Pluggable user interfaces plan

Status: **active — foundation in progress**
Last reviewed: **2026-08-01**

## Decision

The Sufficit Identity runtime must be deployable without a user-interface
implementation. The official public/account UI, the official Management UI and
third-party UIs are presentation adapters, never owners of identity, protocol,
authorization or persistence rules.

Two hosting models are required:

1. **Embedded** — a trusted Razor Class Library is composed into the runtime
   process. This remains the default and simplest Sufficit deployment.
2. **Remote** — a dedicated UI host runs as another process and calls versioned
   HTTP application contracts. The identity runtime remains independently
   available and deployable.

The runtime also supports **None** for a surface. This is the first extraction
gate: it proves that the process starts and serves its non-interactive protocol
and API surfaces without registering or mapping UI services. It does not, by
itself, make browser interaction available remotely.

## Invariants

- UI packages do not reference `Sufficit.Identity.Core`, the active STS,
  persistence projects, ASP.NET Identity managers or OpenIddict managers.
- Embedded UI and HTTP controllers execute the same application use cases.
- A remote UI uses versioned HTTP adapters for those same use cases; it does not
  reproduce business or protocol decisions.
- Installing a same-process UI is a deployment trust decision. Loading arbitrary
  DLLs uploaded through the Management UI is explicitly forbidden.
- Selecting a UI never grants a user a capability. Authorization is re-evaluated
  by the runtime on every protected operation.
- The browser never receives management access or refresh tokens when a BFF is
  used.
- Public interaction state remains server-side. URLs carry only opaque,
  short-lived interaction references and ordinary display/navigation data.
- All state-changing browser requests use antiforgery protection and secure
  cookies appropriate to their topology.

## Target topology

```text
                                    optional same process
                              ┌─────────────────────────────┐
Browser ──> public/account UI ┤                             │
Browser ──> Management UI/BFF ├── application contracts ───┼── runtime adapters
                              │                             │   Identity/OpenIddict
                              └─────────────────────────────┘   persistence/e-mail
                                  embedded or remote HTTP
```

The deployment units become:

- `Sufficit.Identity.Server`: runtime, protocol endpoints, Management API, SCIM,
  health and discovery; no mandatory UI composition;
- official embedded host: composes the runtime with the two official RCLs;
- public/account UI host: optional future remote host;
- Management UI host/BFF: optional future remote host;
- third-party UI package or host: implements the same published contracts and
  passes the conformance kit.

## Contract packages

### `Sufficit.Identity.Application.Abstractions`

A packable assembly containing only commands, projections, results, capability
descriptors and application interfaces. It has no dependency on EF Core,
ASP.NET Identity, OpenIddict or a UI technology.

The neutral interfaces currently located in `Core` and the public portions of
`Management` move here incrementally. Implementations remain in the runtime
projects.

### `Sufficit.Identity.UI.Abstractions`

A small packable assembly containing:

- surface and hosting-mode options;
- module identity and UI contract version;
- semantic interaction endpoint names;
- startup validation metadata;
- no components and no dependency on either official UI.

### Default implementations

The current projects remain the reference implementations:

- `Sufficit.Identity.UI` for public, authentication and account management;
- `Sufficit.Identity.UI.Management` for provider administration.

Their current assembly names and static-asset identities should be preserved
during the extraction to avoid needless consumer breakage.

## Hosting configuration

The first compatible configuration surface is:

```json
{
  "Sufficit": {
    "Identity": {
      "UI": {
        "Public": { "Mode": "Embedded" },
        "Management": { "Mode": "Embedded" }
      }
    }
  }
}
```

`None` skips service registration and endpoint mapping for that surface. The
future `Remote` mode will require an HTTPS base address, issuer/audience
configuration and a supported contract version; it must not silently degrade to
`Embedded` or `None`.

## Embedded module contract

An embedded provider is selected explicitly at build/deployment time:

```csharp
builder.Services
    .AddSufficitIdentity(configuration)
    .AddUserInterface<MyCompanyIdentityUi>()
    .AddManagementInterface<MyCompanyManagementUi>();

app.MapSufficitIdentity();
```

Only one provider may own each surface. Startup fails for duplicate providers,
missing required endpoints or an unsupported UI contract version. A future
configuration selector may choose between providers already compiled into the
host; configuration never loads an arbitrary assembly path.

## Remote Management UI

The separate Management UI follows the Backend-for-Frontend pattern:

1. its server component is a confidential OAuth client;
2. it uses Authorization Code with PKCE;
3. tokens remain in a server-side session;
4. the browser talks only to the BFF using a secure cookie;
5. the BFF calls an allowlisted Sufficit Identity Management API;
6. CSRF protection is mandatory for mutations;
7. tenant/resource/capability checks are repeated by the runtime API.

This topology is suitable for a separate deployment and for a UI implemented in
Blazor, React, Vue or another web stack.

## Remote public/account UI

OIDC defines when the authorization server must interact with the end user, but
does not standardize a remote login-page API. The remote public UI therefore
requires a Sufficit interaction protocol with a narrower boundary than the raw
authorization request.

The runtime will:

1. validate the OAuth/OIDC request first;
2. persist an interaction record server-side;
3. redirect to the selected UI with an opaque, random interaction identifier;
4. expose only the presentation data required for that interaction;
5. accept a command such as authenticate, consent, deny or cancel;
6. consume or rotate the interaction identifier and resume the original
   transaction inside the runtime.

Interaction identifiers are short-lived, audience-bound, one-time by default,
protected against guessing/replay and contain no authorization parameters or
credentials. Return destinations are resolved from runtime-owned state, never
accepted as arbitrary UI input.

For a remote public UI, the preferred deployment keeps the UI/BFF and browser
interaction on one origin. Passwords, passkey ceremonies, MFA and recovery data
are transported only over TLS and are processed through purpose-specific
runtime commands. The UI host does not receive signing keys, stores or protocol
managers.

## Semantic endpoints

Runtime code must stop hard-coding presentation paths. It resolves semantic
endpoint names such as:

- login;
- account creation;
- consent;
- logout confirmation;
- device verification;
- access denied;
- error;
- account management.

An embedded module maps the names locally. A remote provider maps them to an
approved HTTPS origin. Interaction data continues to use query strings when it
is navigation data; sensitive transaction state is represented by the opaque
interaction identifier.

## Conformance kit and author experience

Third-party authors receive:

- a `dotnet new sufficit-identity-ui` template;
- the abstraction packages and reference UI;
- a minimal sample for embedded and remote modes;
- a test kit that verifies endpoint completeness, contract compatibility,
  antiforgery, authorization failure, safe redirects and forbidden dependencies;
- NuGet publishing and deployment documentation;
- an explicit compatibility matrix for runtime and UI contract versions.

The product distinguishes three customization levels: tenant branding, a
trusted embedded UI package and a separately deployed UI/BFF. A theme is data;
an embedded or remote UI is executable code and has a different approval and
operational model.

## Delivery phases

### Phase 0 — decouple registration

- [x] Add neutral hosting options with `Embedded` and `None`.
- [x] Register and map each official UI only in `Embedded` mode.
- [ ] Prove the complete composition executable serves discovery and health,
  while both UI routes stay unmapped, with both surfaces set to `None` against
  the ephemeral MariaDB integration environment. The CI smoke gate is present;
  this item closes after its first successful run.
- [x] Preserve the current default deployment behavior.

### Phase 1 — neutral application contracts

- [ ] Create `Sufficit.Identity.Application.Abstractions`.
- [ ] Move public/account contracts without changing their behavior.
- [ ] Split Management contracts from OpenIddict/EF implementations.
- [ ] Make both official UI projects depend only on abstractions and ASP.NET
  presentation primitives.

### Phase 2 — explicit embedded composition

- [ ] Introduce the versioned module descriptor and semantic endpoints.
- [ ] Move official UI composition out of the API-only server.
- [ ] Add an official embedded composition executable for compatibility.
- [ ] Reject missing, duplicate and incompatible UI modules at startup.

### Phase 3 — remote Management UI

- [ ] Publish the complete versioned Management HTTP contract.
- [ ] Add the standalone BFF host with code flow, PKCE and server-side tokens.
- [ ] Add end-to-end authorization, CSRF, logout and token-leakage tests.

### Phase 4 — remote public interaction

- [ ] Specify and threat-model the opaque interaction protocol.
- [ ] Implement durable distributed interaction state and replay protection.
- [ ] Replace hard-coded UI redirects with semantic endpoint resolution.
- [ ] Cover login, external login, MFA, passkeys, consent, logout, device flow,
  registration and recovery end to end.

### Phase 5 — third-party SDK

- [ ] Publish templates, examples, packages and compatibility policy.
- [ ] Publish and run the conformance kit in CI.
- [ ] Document trusted package approval and remote-provider registration.

## Acceptance gates

- The runtime starts with both UI surfaces set to `None`.
- No UI project or third-party contract package references runtime/persistence
  implementations.
- Embedded and HTTP adapters produce equivalent application outcomes.
- Browser code cannot read OAuth access or refresh tokens in BFF mode.
- Interactive requests cannot be replayed or redirected to an unapproved host.
- Existing embedded routes and assets remain compatible until a versioned
  breaking release explicitly changes them.
- Unsupported remote behavior is rejected at startup and never advertised.

## Normative and implementation references

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0-final.html)
  defines authentication/consent interaction requirements, including
  `prompt=none`; it does not define a remote login UI API.
- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
  governs redirect-based flow hardening and deprecates unsafe patterns.
- [RFC 10017 — OAuth 2.0 for Browser-Based Applications](https://www.rfc-editor.org/rfc/rfc10017.html)
  defines the BFF pattern and keeps tokens out of browser code.
- [RFC 9126 — Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126.html)
  is the reference for validated, opaque authorization request references; the
  Sufficit interaction identifier is a separate internal object and must not
  impersonate a PAR `request_uri`.
- [Duende IdentityServer user interaction options](https://docs.duendesoftware.com/identityserver/reference/v7/options/#userinteraction)
  demonstrate semantic configuration for login, logout, consent, error and
  device-verification pages.
- [ASP.NET Core Razor Class Libraries](https://learn.microsoft.com/aspnet/core/razor-pages/ui-class)
  are the packaging mechanism for trusted embedded implementations.

## Explicit non-goals

- This plan does not start replacing OpenIddict.
- It does not make a third-party UI a protocol authority.
- It does not permit runtime upload or dynamic execution of untrusted code.
- It does not expose the database or framework managers to a UI.
- It does not claim remote public interaction is complete merely because the
  runtime can start with its embedded UI disabled.
