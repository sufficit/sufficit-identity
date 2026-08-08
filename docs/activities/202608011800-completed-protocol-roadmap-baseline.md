# Protocol roadmap baseline — completed

**Date:** 2026-08-01 → 2026-08-05
**Originally:** `docs/plans/PLAN-ROADMAP.md` (sections 2-5, completed portions)

## Completed items

### Production security policy
- ✅ CSP baseline implemented (`SecurityHeadersMiddlewareExtensions`, Report-Only default, tightened `connect-src`)
- ✅ Data Protection keys persisted to DB with at-rest encryption via signing certificate (`ProtectKeysWithCertificate`)
- ✅ Distributed stores for CIBA pending, DPoP nonce, DPoP jti replay (`IDistributedCache`-backed, Redis-ready)

### Protocol interoperability
- ✅ PAR endpoint (`/connect/par`) with global `RequireForAllClients` + per-client requirement
- ✅ FAPI 2.0 enforcement boundary (opt-in client allowlist, PAR/PKCE S256/code-only/DPoP-or-mTLS)
- ✅ JARM independent opt-in (query.jwt, fragment.jwt, form_post.jwt, jwt) + JWE signed-then-encrypted
- ✅ FAPI 2.0 JAR (RFC 9101): signed request objects at authorization + PAR endpoints
- ✅ SSF/CAEP transmitter: session-revoked, credential-change, device-change, assurance-level-change, verification events
- ✅ SSF stream management (RFC 8933): persisted streams, REST API, push + poll delivery (RFC 8934)
- ✅ Subject identifier formats: iss_sub, email, phone, device, jwt-id, uri, opaque, complex
- ✅ Front-channel logout (OIDC Front-Channel Logout 1.0)
- ✅ Back-channel logout (OIDC Back-Channel Logout 1.0, signed logout_token)
- ✅ CIBA (OpenID Connect CIBA Core 1.0): /bc-authorize, poll, complete, distributed pending store

### SCIM interoperability
- ✅ Users + Groups CRUD (RFC 7643/7644)
- ✅ Filtering (eq on userName, externalId, displayName), pagination, PATCH
- ✅ SCIM authorization audit filter (denied requests audited)

### Product quality
- ✅ Independent evaluation performed; the findings listed in this historical baseline were addressed (16/17, M5 by-design). Later hardening work is tracked in the active security plan.

### Evaluation security fixes (EVALUATION-2026-08-04-GLM-5.2)
- ✅ H4: in-memory stores → distributed
- ✅ M1: scope/capability namespace separation
- ✅ M2: role god-mode → granular RoleCapabilities + opt-in FullAdministratorRoles
- ✅ M6: CSP connect-src ws/wss wildcard removed
- ✅ M7: branding CSS injection sanitized (regex + render-site SafeColor/SafeUrl)
- ✅ L1: device user-code oracle (removed client info from anonymous endpoint)
- ✅ L2: CIBA binding_message capped (180 chars)
- ✅ L4: email test-address redirect production guard
- ✅ L5: SCIM denied requests audit filter
- ✅ L6: consent page antiforgery token
- ✅ L7: Permissions-Policy + COOP + CORP headers
- ✅ L8: DataProtection keys encrypted at rest
- ✅ L10: breached-password validator (HIBP range API)
