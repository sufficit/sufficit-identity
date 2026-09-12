# RFC and specification compliance

One document per specification: what this server implements, **how**,
and how far it goes. The source of truth is the code; every claim here cites
`file:line`. When code and text diverge, the code wins and this
document is the one that's wrong.

## Coverage scale

| Level | Meaning |
|---|---|
| **A — Complete** | Every `MUST` and every applicable `SHOULD` for the role played, with an automated test. |
| **B — Substantial** | Every `MUST`; some `SHOULD` or optional feature missing, listed in the document. |
| **C — Partial** | Interoperable subset in production, with relevant gaps stated. |
| **D — Minimal** | Only what's needed for another feature to work; not an implementation of the profile. |
| **— Absent** | Not implemented, by recorded decision. |

The role played matters: in almost everything, Identity is an **Authorization
Server** (AS) or an **OpenID Provider** (OP). Requirements aimed at the client
or at the resource server don't count against the grade, and are marked as
out of scope.

## Implementation origin

| Origin | Meaning |
|---|---|
| `OpenIddict` | Behavior inherited from OpenIddict 7.7 and only configured here. |
| `In-house` | Written in this repository, because OpenIddict doesn't cover it. |
| `Mixed` | OpenIddict base with in-house handlers in the event pipeline. |

## Index — IETF

| RFC | Subject | Level | Origin | Document |
|---|---|---|---|---|
| 6749 | OAuth 2.0 Authorization Framework | B | OpenIddict | [RFC-6749-OAUTH2-CORE.md](RFC-6749-OAUTH2-CORE.md) |
| 6750 | Bearer Token Usage | A | OpenIddict | [RFC-6750-BEARER-TOKEN.md](RFC-6750-BEARER-TOKEN.md) |
| 7009 | Token Revocation | A | OpenIddict | [RFC-7009-TOKEN-REVOCATION.md](RFC-7009-TOKEN-REVOCATION.md) |
| 7519 + JOSE | JWT, JWS, JWE, JWK, JWA | B | Mixed | [RFC-7519-JWT-AND-JOSE.md](RFC-7519-JWT-AND-JOSE.md) |
| 7523 | JWT client assertions (`private_key_jwt`) | B | OpenIddict | [RFC-7523-CLIENT-ASSERTION.md](RFC-7523-CLIENT-ASSERTION.md) |
| 7591 | Dynamic Client Registration | C | In-house | [RFC-7591-DYNAMIC-CLIENT-REGISTRATION.md](RFC-7591-DYNAMIC-CLIENT-REGISTRATION.md) |
| 7636 | PKCE | A | OpenIddict | [RFC-7636-PKCE.md](RFC-7636-PKCE.md) |
| 7643/7644 | SCIM 2.0 | C | In-house | [RFC-7643-7644-SCIM.md](RFC-7643-7644-SCIM.md) |
| 7662 | Token Introspection | A | OpenIddict | [RFC-7662-TOKEN-INTROSPECTION.md](RFC-7662-TOKEN-INTROSPECTION.md) |
| 8176 | Authentication Method Reference (`amr`) | C | In-house | [RFC-8176-AMR-VALUES.md](RFC-8176-AMR-VALUES.md) |
| 8252 | OAuth 2.0 for Native Apps | B | In-house | [RFC-8252-NATIVE-APPS.md](RFC-8252-NATIVE-APPS.md) |
| 8414 | Authorization Server Metadata | A | Mixed | [RFC-8414-AUTHORIZATION-SERVER-METADATA.md](RFC-8414-AUTHORIZATION-SERVER-METADATA.md) |
| 8417/8935/8936 | Security Event Token and delivery | B | In-house | [RFC-8417-SECURITY-EVENT-TOKEN.md](RFC-8417-SECURITY-EVENT-TOKEN.md) |
| 8628 | Device Authorization Grant | A | Mixed | [RFC-8628-DEVICE-AUTHORIZATION-GRANT.md](RFC-8628-DEVICE-AUTHORIZATION-GRANT.md) |
| 8693 | Token Exchange | C | Mixed | [RFC-8693-TOKEN-EXCHANGE.md](RFC-8693-TOKEN-EXCHANGE.md) |
| 8705 | Mutual-TLS client auth and bound tokens | B | Mixed | [RFC-8705-MUTUAL-TLS.md](RFC-8705-MUTUAL-TLS.md) |
| 8707 | Resource Indicators | B | Mixed | [RFC-8707-RESOURCE-INDICATORS.md](RFC-8707-RESOURCE-INDICATORS.md) |
| 9068 | JWT Profile for Access Tokens | B | Mixed | [RFC-9068-JWT-ACCESS-TOKEN.md](RFC-9068-JWT-ACCESS-TOKEN.md) |
| 9101 | JWT-Secured Authorization Request (JAR) | B | In-house | [RFC-9101-JAR.md](RFC-9101-JAR.md) |
| 9126 | Pushed Authorization Requests (PAR) | A | Mixed | [RFC-9126-PAR.md](RFC-9126-PAR.md) |
| 9207 | Authorization Server Issuer Identification | A | OpenIddict | [RFC-9207-ISSUER-IDENTIFICATION.md](RFC-9207-ISSUER-IDENTIFICATION.md) |
| 9449 | DPoP | B | In-house | [RFC-9449-DPOP.md](RFC-9449-DPOP.md) |
| 9700 | OAuth 2.0 Security Best Current Practice | B | Mixed | [RFC-9700-OAUTH-SECURITY-BCP.md](RFC-9700-OAUTH-SECURITY-BCP.md) |
| 9728 | Protected Resource Metadata | B | In-house | [RFC-9728-PROTECTED-RESOURCE-METADATA.md](RFC-9728-PROTECTED-RESOURCE-METADATA.md) |

## Index — OpenID Foundation, W3C and drafts

| Specification | Level | Origin | Document |
|---|---|---|---|
| OpenID Connect Core 1.0 | B | Mixed | [SPEC-OIDC-CORE.md](SPEC-OIDC-CORE.md) |
| OpenID Connect Discovery 1.0 | A | Mixed | [SPEC-OIDC-DISCOVERY.md](SPEC-OIDC-DISCOVERY.md) |
| RP-Initiated, Front-Channel and Back-Channel Logout | B | Mixed | [SPEC-OIDC-LOGOUT.md](SPEC-OIDC-LOGOUT.md) |
| CIBA Core 1.0 | C | In-house | [SPEC-OIDC-CIBA.md](SPEC-OIDC-CIBA.md) |
| JARM | B | In-house | [SPEC-JARM.md](SPEC-JARM.md) |
| FAPI 2.0 Security Profile | C | In-house | [SPEC-FAPI-2-0.md](SPEC-FAPI-2-0.md) |
| Shared Signals Framework, CAEP and RISC | C | In-house | [SPEC-SSF-CAEP-RISC.md](SPEC-SSF-CAEP-RISC.md) |
| WebAuthn Level 2 and passkeys | B | ASP.NET Identity | [SPEC-WEBAUTHN-PASSKEYS.md](SPEC-WEBAUTHN-PASSKEYS.md) |
| OAuth Client ID Metadata Document (draft) | B | In-house | [SPEC-OAUTH-CIMD.md](SPEC-OAUTH-CIMD.md) |
| MCP Authorization | B | Mixed | [SPEC-MCP-AUTHORIZATION.md](SPEC-MCP-AUTHORIZATION.md) |

## Not implemented, by decision

| Specification | Reason |
|---|---|
| SAML 2.0 | Out of the product's scope; no SAML consumer. |
| OpenID Connect Session Management 1.0 (`check_session_iframe`) | Replaced by server-side sessions and back-channel logout; the iframe depends on third-party cookies. |
| Identity Assertion JWT Authorization Grant (ID-JAG) | Draft; evaluated as the next step for agent-to-agent application access. |
| OAuth 2.0 Device Posture / RFC 9396 (RAR) | No demand; `scope` + `resource` cover the current cases. |
| Implicit and Hybrid flow | Deliberately removed — see [RFC-9700-OAUTH-SECURITY-BCP.md](RFC-9700-OAUTH-SECURITY-BCP.md). |
| Resource Owner Password Credentials | Off by default, kept only as migration compatibility. |
