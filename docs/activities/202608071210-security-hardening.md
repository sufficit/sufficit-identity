# Endurecimento de segurança, sessão e vault — trabalho concluído

**Período:** 2026-08-06 → 2026-08-07
**Versão validada:** `f97ef7e`

## Closed findings

### Protocol and authentication hardening
- ✅ **H1 — complete credential-surface rate limiting:** every `POST /connect/*`, CIBA initiation at `/bc-authorize`, and the interactive account credential endpoints pass through the per-IP limiter (`Server/Program.cs`)
- ✅ **M5 — external-login sign-in policy alignment:** newly created external users pass through `SignInManager.CanSignInAsync`; Google, GitHub, and Facebook project provider verification into `email_verified` (`AspNetCoreIdentityExternalSignInService`, `ServiceCollectionExtensions`)
- ✅ **M6 — CIBA token lifecycle:** manually signed CIBA access tokens receive an OpenIddict token entry and payload, with end-to-end introspection, revocation, one-shot issuance, and concurrent-consume coverage (`CibaController`, `CibaAccessTokenGenerator`, `CibaTests`)
- ✅ **L1 — bounded personal-token lifetime:** administrator and regular-user personal access tokens are capped at 365 days (`PersonalTokensController`)

### Management and secret boundaries
- ✅ **M1 — production client-secret resolver:** the composition host replaces the fail-closed placeholder with `VaultBackedClientSecretResolver`; confidential-client provisioning no longer depends on an unimplemented resolver
- ✅ **M3 — reserved administrative scopes:** `ManagementOptions.ReservedApiScopes` defaults to `identity.management` and `scim`; runtime scope creation and client assignment reject these scopes (`ScopeManagementService`, `ClientManagementService`)
- ✅ **L3 — read-path audit noise:** list/search reads no longer emit one database audit record per page; state-changing operations remain audited
- ✅ **Vault Phase 1:** `Sufficit.Identity.Vault` provides envelope encryption, versioned wrapped keys, ciphertext migration support, tests, and production enforcement capability; this is the completed software foundation only—migration and rotation of ignored runtime assets remain open in the plan

### Session, state, and presentation hardening
- ✅ **Server-side sessions:** the Identity application cookie uses a database-backed `ITicketStore`; sessions are enumerable, revocable, protected with Data Protection, and shared across replicas (`OidcUserSessionTicketStore`, `OidcUserSession`)
- ✅ **Multi-replica configuration guard:** production startup can fail fast when shared distributed state is required but only `MemoryDistributedCache` is registered (`DistributedCacheOptions.RequireShared`)
- ✅ **L4 — branding CSS boundary:** background URLs are normalized and projected through `BrandingThemeProvider.SafeCssUrl`, which rejects CSS string-breakout characters and permits only HTTPS absolute URLs or rooted relative paths

## Completed foundations for risks that remain open

These components are implemented and tested, but they are prerequisites rather than full closure of the corresponding finding. The remaining work is tracked in the planos canônicos de autorização e produção.

- ✅ **H2 foundation:** reserved-scope blocking now prevents minting the management/SCIM transport scopes through runtime CRUD
- ✅ **H3 foundation:** `IManagementObjectAccessPolicy` is invoked after capability and MFA checks, with denial propagated by the evaluator; the default implementation intentionally remains permissive
- ✅ **M2 foundation:** SCIM has an optional `ScimMfaRequirement`/handler and can require MFA evidence through configuration
- ✅ **M4 foundation:** SCIM requires an explicit `client_id`/`azp` allow-list and fails closed when the list is empty

## Delivery evidence

- `51f2086` — server-side sessions, full protocol rate-limit coverage, SCIM MFA boundary, external-login policy alignment, reserved-scope checks
- `8fc026e` — object-level authorization extension point and evaluator integration
- `0f1f92d` — fail-closed SCIM client allow-list
- `2978005` — PAT lifetime reduction and read-audit cleanup
- `e89a6bc`, `19ac081`, `b9e7c5f` — vault, client-secret resolver, and encryption migration support
- `89b3a56`, `30a793d` — CIBA lifecycle/state hardening and revocation/introspection coverage
