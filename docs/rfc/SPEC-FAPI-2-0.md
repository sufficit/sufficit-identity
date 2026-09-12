# FAPI 2.0 Security Profile

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **C — Partial** (implemented, **not certified**) |
| Origin | In-house |
| Spec | https://openid.net/specs/fapi-security-profile-2_0-final.html |

The FAPI 2.0 Security Profile has been a **Final** specification since
February 2025. The repository implements the controls, but **has never run
the OpenID Foundation's conformance suite**. That is why the level is C: the
behavior exists, the external proof does not.

## Activation

`Sufficit:Identity:Fapi2:Enabled`, with per-client application decided in
`Fapi2Policy.Applies` (`src/sts/Fapi/Fapi2Handlers.cs:14`). Three handlers
enter the pipeline (`src/sts/OpenIddictServerConfiguration.cs:267-276`):

| Handler | Point |
|---|---|
| `ValidateFapiAuthorizationRequest` | `/connect/authorize` |
| `ValidateFapiPushedAuthorizationRequest` | `/connect/par` |
| `ValidateFapiTokenRequest` | `/connect/token` |

## What is rejected

At PAR and at authorize (`Fapi2Handlers.cs:127-182`):

| Condition | Error |
|---|---|
| Client not authenticated via `private_key_jwt` or mTLS | `invalid_client` |
| `response_type` other than `code` | `unsupported_response_type` |
| `redirect_uri` missing | `invalid_request` |
| `code_challenge` missing or method other than `S256` | `invalid_request` |
| `SenderConstraint=DPoP` and `dpop_jkt` missing or invalid | `invalid_request` |
| Client without PAR when the profile requires it | `unauthorized_client` |

At the token endpoint (`:214-232`): weak authentication is rejected, and with
`SenderConstraint=Mtls` the certificate must be present and bound.

## Lifetimes

The profile shortens two values, globally, because OpenIddict does not
expose them per client (`src/sts/OpenIddictServerConfiguration.cs:268-275`):

| Value | Key |
|---|---|
| Authorization code | `Fapi2:AuthorizationCodeLifetimeSeconds` |
| PAR `request_uri` | `Fapi2:PushedAuthorizationRequestLifetimeSeconds` |

Applying it globally is conservative: it also shortens lifetimes for clients
outside the profile, which stays backward compatible.

## Cross-validation at startup

`src/sts/ServiceCollectionExtensions.Validation.cs:135-141` rejects
inconsistent configuration: `SenderConstraint=DPoP` with `Dpop:Enabled=false`
fails the process, instead of running a profile that cannot deliver on what
it promises.

## Composition

FAPI 2.0 here is the sum of other pieces, not a standalone implementation:

- [RFC-9126-PAR.md](RFC-9126-PAR.md) — mandatory `request_uri`
- [RFC-7636-PKCE.md](RFC-7636-PKCE.md) — `S256`
- [RFC-9449-DPOP.md](RFC-9449-DPOP.md) or
  [RFC-8705-MUTUAL-TLS.md](RFC-8705-MUTUAL-TLS.md) — proof-of-possession
  binding
- [RFC-7523-CLIENT-ASSERTION.md](RFC-7523-CLIENT-ASSERTION.md) — strong
  authentication
- [RFC-9207-ISSUER-IDENTIFICATION.md](RFC-9207-ISSUER-IDENTIFICATION.md) —
  anti mix-up
- [SPEC-JARM.md](SPEC-JARM.md) — signed response (Advancing profile)

## Gaps

| Item | Status |
|---|---|
| FAPI 2.0 conformance suite in CI | No |
| FAPI 2.0 Message Signing | Partial, via JARM; no HTTP request signing |
| FAPI 1.0 Advanced | No |
| Mandatory `request` object in the profile | Not enforced; PAR is the path taken |

## Tests

`FapiJarmTests`, `FapiJarmTests.Par`, `FapiJarmTests.Jarm`, `SenderConstraintTests`,
`MtlsPolicyTests`.
