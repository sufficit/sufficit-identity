# RFC 7521 / RFC 7523 — JWT client assertions (`private_key_jwt`)

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **B — Substantial** |
| Origin | OpenIddict, with an in-house client JWKS policy |
| Spec | https://www.rfc-editor.org/rfc/rfc7523 |

## Implementation

`private_key_jwt` is enabled **unconditionally** by OpenIddict; there is no
flag to turn it off (note in `src/sts/OpenIddictServerConfiguration.cs:60-62`).
The client authenticates at the token endpoint by presenting
`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
and a JWT signed with a key whose public counterpart is registered.

Registration of these keys is in-house: `src/management/Clients/ClientJwksPolicy.cs`
validates both the inline JWKS and the `jwks_uri`.

| Rule enforced | Where |
|---|---|
| `jwks_uri` must be absolute HTTPS, public, without user-info or fragment | `ClientJwksPolicy.cs:37-50` |
| Only public `RSA` or `EC` keys | `ClientJwksPolicy.cs:135-140` |
| `kid` required and unique within the set | `ClientJwksPolicy.cs:144-149` |
| Limit on the number of keys | `ClientJwksPolicy.cs:23` |
| Remote fetch of `jwks_uri` goes through the anti-SSRF guard | `src/sts/SafeHttpHandlerFactory.cs` |

## Where it's required

- **FAPI 2.0**: the client must authenticate with `private_key_jwt` **or** mTLS;
  a shared secret is rejected
  (`src/sts/Fapi/Fapi2Handlers.cs:151` and `:226`).
- Other confidential clients can use `client_secret_basic` or
  `client_secret_post`, with the secret stored only as a hash — see
  [RFC-6749-OAUTH2-CORE.md](RFC-6749-OAUTH2-CORE.md).

## Inherited security fix

OpenIddict 7.7 fixed `aud` validation in client assertions
(GHSA-925x-4h4v-2792) and started accepting `aud` as a JSON array. The repository
is on that version (`Directory.Packages.props`), so the fix is
present.

## Gaps

- The `urn:ietf:params:oauth:grant-type:jwt-bearer` grant (RFC 7523 §2.1,
  *authorization* by assertion, not authentication) is **not** enabled. It's the
  piece that would be missing for the ID-JAG draft.
- There's no assisted rotation of the client's JWKS; the operator swaps the document.

## Tests

`ClientsControllerTests.Credentials`, `ClientDefinitionPolicyTests`,
`FapiJarmTests`, `JarRequestObjectTests` (reuses key resolution).
