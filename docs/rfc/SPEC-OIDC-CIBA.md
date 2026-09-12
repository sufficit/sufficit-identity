# OpenID Connect Client-Initiated Backchannel Authentication (CIBA) Core 1.0

| | |
|---|---|
| Role | OpenID Provider |
| Coverage | **C — Partial** |
| Origin | In-house — OpenIddict has no CIBA primitives |
| Spec | https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html |

## Surface

`src/sts/Controllers/CibaController.cs`, with state persisted in
`cibapendingstates`.

| Role | Path | Line |
|---|---|---|
| Backchannel authentication (§7) | `POST /bc-authorize` | `:101` |
| User approval | `GET`/`POST /connect/ciba/complete` | `:191`, `:251` |
| Token polling (§10) | `POST /connect/ciba/token` | `:343` |

## Supported mode

**Poll** only. `ping` and `push` are not implemented.

| Requirement | § | Status |
|---|---|---|
| Opaque `auth_req_id` | 7.3 | Yes |
| `expires_in` and `interval` in the response | 7.3 | Yes, from `CibaOptions` |
| `login_hint` resolving the user | 7.1 | Yes, email or username |
| `binding_message` shown before approval | 7.1 | Yes, with a size limit (`:114-119`) |
| `authorization_pending` / `slow_down` | 11 | Yes |
| `expired_token` / `access_denied` | 11 | Yes |
| Per-client scope permission checked | 7.1 | Yes (`:160-162`) |
| Client eligibility policy | — | Yes, `ICibaClientPolicy` with `Observe` mode reported by the posture check |
| `user_code` | 7.1 | No |
| `id_token_hint` as identifier | 7.1 | No |
| `ping` / `push` mode | 10.2, 10.3 | No |

## Relevant architectural deviation

The spec defines polling at the **standard token endpoint**, with
`grant_type=urn:openid:params:grant-type:ciba`. Here polling happens at
`/connect/ciba/token`, an in-house endpoint, and client authentication is
reimplemented by reading `client_secret` from the form body (`:111`, `:351`).

Three practical consequences:

1. An off-the-shelf CIBA client doesn't work without adaptation.
2. `private_key_jwt`, mTLS and the DPoP nonce dance **don't** automatically
   apply to this path, because it doesn't go through the OpenIddict pipeline.
3. There's a second client-authentication implementation to review and
   maintain.

The proposed design fix is to register the grant with `AllowCustomFlow` and
implement a `CibaGrantHandler : ITokenGrantHandler`, eliminating the in-house
endpoint and inheriting all existing client authentication.

## Token issuance

`src/sts/Ciba/CibaAccessTokenGenerator.cs` assembles the access token directly,
and is the only place in the repository that explicitly stamps `typ: at+jwt`
(`:124`), pinned by `CibaTests.cs:166`.

## Tests

`CibaTests`.
