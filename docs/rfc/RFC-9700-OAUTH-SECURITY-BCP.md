# RFC 9700 — OAuth 2.0 Security Best Current Practice

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **B — Substantial** |
| Origin | Mixed — this is a cross-cutting document, not a feature |
| Spec | https://www.rfc-editor.org/rfc/rfc9700 |

This document does not describe an endpoint; it audits the repository
against the BCP's recommendations. It is the conformance summary an external
reviewer asks for first.

## Main recommendations

| Recommendation | § | Status | Where |
|---|---|---|---|
| Do not use the implicit grant | 2.1.2 | **Met**, not registered | `OpenIddictServerConfiguration.cs:243-247` |
| Do not use Resource Owner Password Credentials | 2.4 | **Met by default**, disabled | `:296-297` |
| PKCE for all code clients | 2.1.1 | **Met** | [RFC-7636-PKCE.md](RFC-7636-PKCE.md) |
| Exact `redirect_uri` comparison | 4.1 | Met | `ClientUriPolicy.cs` |
| Refresh token rotation or client binding | 4.14 | **Met**, single-use rotation with reuse detection | `:358-372` |
| `iss` in the authorization response (anti mix-up) | 4.4 | Met | [RFC-9207-ISSUER-IDENTIFICATION.md](RFC-9207-ISSUER-IDENTIFICATION.md) |
| Sender-constrained tokens | 4.10 | Met, DPoP and mTLS | [RFC-9449-DPOP.md](RFC-9449-DPOP.md), [RFC-8705-MUTUAL-TLS.md](RFC-8705-MUTUAL-TLS.md) |
| Restrict token audience | 4.9 | Met | [RFC-8707-RESOURCE-INDICATORS.md](RFC-8707-RESOURCE-INDICATORS.md) |
| No credentials in query string | 4.3 | Met | — |
| CSRF protection on interactive steps | 4.7 | Met, antiforgery validated server-side at consent, logout and device | `AuthorizationController.cs:260-275` |
| Clickjacking countermeasure | 4.5 | Met, CSP and security headers | `SecurityHeadersMiddlewareExtensions.cs` |
| Limit code lifetime | 4.1 | Met, and shortened under FAPI | `:270-272` |
| Strong client authentication | 4.13 | Available: `private_key_jwt` and mTLS; mandatory under FAPI | [RFC-7523-CLIENT-ASSERTION.md](RFC-7523-CLIENT-ASSERTION.md) |
| Client secrets not stored in cleartext | — | Met, `PasswordHasher` V3 | `src/core/Services/ClientCredentialSecretHasher.cs:24-27` |

## Additional mitigations, beyond the BCP

| Control | Where |
|---|---|
| Posture check that refuses to start in production with an unacknowledged finding | `src/sts/Security/ProductionPostureCheck.cs` |
| Rate limiting per endpoint group, with a separate bucket for introspection, PAR, device-info and administration | `src/server/IdentityRateLimitPolicy.cs` |
| Anti-SSRF guard on every outbound HTTP call (remote JWKS, CIMD, HIBP, SSF push) | `src/sts/SafeHttpHandlerFactory.cs` |
| Account lockout and a 12-character password policy | `src/sts/Options/AccountPolicyOptions.cs:14-48` |
| Breached password check (HIBP, k-anonymity) | `src/sts/BreachedPasswordValidator.cs` |
| Server-side sessions, revocable per device | `src/sts/OidcUserSessionTicketStore.cs` |
| Cascading revocation on credential change | `src/sts/CredentialMutationSecurityCoordinator.cs:114-155` |

## Known attention points

| Item | Risk | Note |
|---|---|---|
| Empty `Sufficit:Identity:Issuer` | `iss` follows the `Host` header | Always configure it |
| `RateLimit:FailOnUntrustedProxy = false` | Without trusted proxies, the per-IP limit collapses into a single bucket | Enable in production |
| `Password:RejectBreached = false` | HIBP disabled by default, and fails open | Enable in production |
| Password grant with timing enumeration | The hash is only computed when the user exists | Grant disabled by default |
| External identity linking without `email_verified` | Fixed: no account is created or bound until control of the address is proven | See [ARCHITECTURE-EXTERNAL-IDENTITY-LINKING.md](../architecture/ARCHITECTURE-EXTERNAL-IDENTITY-LINKING.md) |

The remaining items are detailed, with scenario and fix, in the most recent
independent evaluation under `docs/evaluations/`.
