# JARM — JWT Secured Authorization Response Mode

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **B — Substantial** |
| Origin | In-house |
| Spec | https://openid.net/specs/oauth-v2-jarm.html |

## Implementation

Enabled by `Sufficit:Identity:Jarm:Enabled` (default `false`). When active,
four response modes are added to OpenIddict and a handler takes over writing
the response (`src/sts/OpenIddictServerConfiguration.cs:277-285`):

| `response_mode` | Constant |
|---|---|
| `jwt` | `JarmAuthorizationResponseHandler.Jwt` |
| `query.jwt` | `QueryJwt` |
| `fragment.jwt` | `FragmentJwt` |
| `form_post.jwt` | `FormPostJwt` |

`src/sts/Jarm/JarmAuthorizationResponseHandler.cs:16-19`. A mode outside
these four is not handled (`:50`), and the response follows the normal path.

## Content and signing

The response becomes a JWT signed with the auxiliary credential, with a
120-second lifetime by default (`src/sts/Options/JarmOptions.cs:19`). The
algorithm is published in `authorization_signing_alg_values_supported`
(`src/sts/OpenIddictServerConfiguration.cs:597-601`).

What JARM protects: in `query.jwt` the response parameters no longer travel
in cleartext in the URL, and instead become a signed object. This gives
integrity and origin authentication to the authorization response —
including error responses, which without JARM are forgeable by whoever
controls the redirect.

## Encryption

Optional (`Jarm:Encryption:Enabled`, default `false`). When enabled, it
resolves the client's encryption credentials
(`IJarmClientEncryptionCredentialsResolver`) and produces a JWE with:

| Parameter | Default |
|---|---|
| RSA key management | `RSA-OAEP-256` |
| EC key management | `ECDH-ES+A256KW` |
| Content encryption | `A256CBC-HS512` |

`src/sts/Options/JarmOptions.cs:59-74`. All three are published in discovery
when encryption is active, as required by the FAPI 2.0 Advancing profile.

## Gaps

- No per-client algorithm selection: the `alg` is the OP's auxiliary
  credential's.
- `authorization_encryption_*` are global, not per client registration.

## Tests

`FapiJarmTests`, `FapiJarmTests.Jarm`.
