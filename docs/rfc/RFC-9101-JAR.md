# RFC 9101 — JWT-Secured Authorization Request (JAR)

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **B — Substantial** |
| Origin | In-house — OpenIddict does not implement JAR |
| Spec | https://www.rfc-editor.org/rfc/rfc9101 |

## Implementation

Two event handlers, registered only when `Sufficit:Identity:Jar:Enabled`
(`src/sts/OpenIddictServerConfiguration.cs:287-294`):

| Handler | Point |
|---|---|
| `ExtractAuthorizationRequestObject` | `/connect/authorize` |
| `ExtractPushedAuthorizationRequestObject` | `/connect/par` |

Both in `src/sts/Jar/JarRequestObjectHandler.cs`. They extract the `request`
parameter, validate it, and merge the object's claims into the request.

## Validation, in the order the code runs it

| # | Check | Line |
|---|---|---|
| 1 | Parsed without validation, only to read `alg`/`kid` | `:129` |
| 2 | `iat`, `exp` and `jti` required; `exp > iat` | `:154-162` |
| 3 | `iat` at most 30 s in the future; `exp - iat` window bounded | `:170-171` |
| 4 | `alg` on the allow-list (`PS256`, `ES256` by default) | `:179-183` |
| 5 | `client_id` present in the object and equal to the one in the outer request | `:187-200` |
| 6 | Resolution of the client's keys via `jwks` or `jwks_uri` | `:205-241` |
| 7 | Signature validation with `ValidateIssuer` and `ValidateAudience` on: `iss` = `client_id`, `aud` = OP issuer | `:245-252` |

Step 4 is what closes off the algorithm-confusion attack family: `none` and
symmetric algorithms are not on the list and cannot be negotiated by the
client.

Step 5 closes off client substitution: an object signed by A cannot be
presented as a request from B.

## Remote keys

`src/sts/Jar/JarSigningKeyResolver.cs` fetches `jwks_uri` through
`SafeHttpHandlerFactory` (anti-SSRF guard, no redirection into the internal
network) and keeps a cache with a fixed TTL — a code comment records that
honoring `Cache-Control` (RFC 9111) was deliberately traded for a fixed TTL,
so that a hostile server cannot force infinite revalidation.

## Discovery

With JAR enabled, the document publishes `request_parameter_supported: true`
and `request_object_signing_alg_values_supported` with the ordered allow-list
(`src/sts/OpenIddictServerConfiguration.cs:625-634`).

## Gaps

- `request_uri` **by client value** (§5.2.2, fetching the object from a URL
  hosted by the client) is not supported. The `request_uri` accepted is the
  PAR one, which belongs to the AS itself — which is the FAPI 2.0
  recommendation anyway.
- Encrypted (JWE) request objects on input are not supported; only signed
  ones.

## Tests

`JarRequestObjectTests`, `FapiJarmTests.Par`.
