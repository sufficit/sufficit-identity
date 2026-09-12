# RFC 7519 and the JOSE family — JWT, JWS, JWE, JWK, JWA

| | |
|---|---|
| Role | Issuer and verifier |
| Coverage | **B — Substantial** |
| Origin | Mixed: `Microsoft.IdentityModel` via OpenIddict, plus the in-house vault |
| Specs | RFC 7515 (JWS), 7516 (JWE), 7517 (JWK), 7518 (JWA), 7519 (JWT) |

## Where JWTs appear

| Use | Format | Signed by |
|---|---|---|
| `id_token` | JWS | OP's signing key |
| Self-contained access token | JWS (`at+jwt`) | OP's signing key |
| Access token by reference | Opaque, not a JWT | — |
| `logout_token` (back-channel) | JWS | Auxiliary credential |
| JARM (`response=`) | JWS, optionally JWE | Auxiliary credential |
| Security Event Token (SSF/CAEP) | JWS (`secevent+jwt`) | Auxiliary credential |
| DPoP proof (inbound) | JWS (`dpop+jwt`) | Client key |
| JAR request object (inbound) | JWS | Client key |
| Client assertion (inbound) | JWS | Client key |

OpenIddict's internal tokens (authorization code, refresh, device code)
are **encrypted** with the encryption certificate, which is why the deployment requires
`Certificates:EncryptionPath` in production
(`src/sts/OpenIddictServerConfiguration.cs:481-489`).

## Algorithms

| Context | Accepted | Origin |
|---|---|---|
| OP token signing | `RS256`, `PS256`, `ES256` | `src/vault/SigningAlgorithms.cs:18-20` |
| DPoP proof | `ES256`, `RS256` | `src/sts/Dpop/DpopProofValidator.cs` (`alg` check) |
| JAR request object | `PS256`, `ES256` by default | `src/sts/Options/JarOptions.cs:30-33` |
| JARM's JWE | `RSA-OAEP-256` / `ECDH-ES+A256KW` with `A256CBC-HS512` | `src/sts/Options/JarmOptions.cs:59-74` |
| Client JWKS | Only public `RSA` and `EC` keys, with a unique `kid` | `src/management/Clients/ClientJwksPolicy.cs:135-149` |

No path accepts `none` or a symmetric algorithm coming from the client: every
list is an explicit allow-list. This closes the algorithm-confusion attack
class described in RFC 8725.

## Key publication (JWK Set)

`GET /.well-known/openid-configuration/jwks`
(`src/sts/OpenIddictServerConfiguration.cs:51`). When the vault manages the
keys (`Vault:ManageSigningKeys`), the JWKS is rewritten by
`VaultJsonWebKeySetHandler` to publish the vault's keys and **remove** the
ephemeral bootstrap key that OpenIddict requires for options validation
(`src/sts/OpenIddictServerConfiguration.cs:437-450`).

Rotation: `KeyVault.RotateKeyAsync` creates a new version under a distributed
*lease*; the old versions keep verifying, which gives overlap without downtime
(`src/vault/KeyVault.cs`, `src/vault/KeyVault.Signing.cs`).

## Gaps

- `typ: at+jwt` is not explicitly stamped on the self-contained access token —
  see [RFC-9068-JWT-ACCESS-TOKEN.md](RFC-9068-JWT-ACCESS-TOKEN.md).
- No support for post-quantum algorithms; OpenIddict 8.0 preview introduced
  ML-DSA, not yet adopted here.

## Tests

`VaultSigningAlgorithmTests`, `VaultTests.Signing`, `CertificateRotationTests`,
`DiscoveryTests`.
