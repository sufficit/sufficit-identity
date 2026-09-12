# RFC 7636 — Proof Key for Code Exchange

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **A — Complete** |
| Origin | OpenIddict, with an in-house enforcement policy |
| Spec | https://www.rfc-editor.org/rfc/rfc7636 |

## Implementation

Three layers, in `src/sts/OpenIddictServerConfiguration.cs:314-322`:

1. `server.RequireProofKeyForCodeExchange()` when
   `Sufficit:Identity:Pkce:RequireForAllClients` — enforces PKCE for **every**
   `authorization_code` client, including confidential ones, which goes beyond RFC 7636
   (which only requires it for public clients) and follows OAuth 2.1.
2. Removal of `plain` from the list of accepted methods, unless explicit opt-in via
   `Sufficit:Identity:Pkce:AllowPlainCodeChallengeMethod`. Without that opt-in,
   only `S256` is accepted.
3. Per-client requirement: every client created through the management plane or via
   DCR is born with `Requirements.Features.ProofKeyForCodeExchange`
   (`src/management/Clients/ClientManagementService.Mutations.cs:241-242`,
   `src/sts/Controllers/RegistrationController.cs:149`).

| Requirement | § | Status |
|---|---|---|
| `code_challenge` at authorize | 4.3 | Yes |
| `code_verifier` at token | 4.5 | Yes |
| `S256` verification | 4.6 | Yes |
| `plain` discouraged | 7.2 | Yes, removed by default |
| `invalid_grant` error on wrong verifier | 4.6 | Yes |

## Interaction with FAPI 2.0 and PAR

Under FAPI 2.0, PKCE remains mandatory and adds to the `dpop_jkt` or mTLS
binding — see [SPEC-FAPI-2-0.md](SPEC-FAPI-2-0.md). The `code_challenge` enters via
PAR when the client uses `request_uri`
([RFC-9126-PAR.md](RFC-9126-PAR.md)).

## Configuration

| Key | Recommended default | Effect |
|---|---|---|
| `Sufficit:Identity:Pkce:RequireForAllClients` | `true` | PKCE required for everyone. |
| `Sufficit:Identity:Pkce:AllowPlainCodeChallengeMethod` | `false` | Keeps only `S256`. |

## Tests

`AuthorizationCodeFlowTests`, `ParLoginRoundTripTests`,
`src/tests/Infrastructure/Pkce.cs` (verifier/challenge pair generation).
