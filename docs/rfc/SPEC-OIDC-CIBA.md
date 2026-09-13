# OpenID Connect Client-Initiated Backchannel Authentication (CIBA) Core 1.0

| | |
|---|---|
| Role | OpenID Provider |
| Coverage | **C — Partial** |
| Origin | In-house initiation and approval; polling through the token endpoint |
| Spec | https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html |

## Surface

Initiation and approval live in `src/sts/Controllers/CibaController.cs`;
polling is the custom grant `src/sts/Grants/CibaGrantHandler.cs`. State is
persisted in `cibapendingstates`.

| Role | Path |
|---|---|
| Backchannel authentication (§7) | `POST /bc-authorize` |
| User approval | `GET`/`POST /connect/ciba/complete` |
| Token polling (§10.1) | `POST /connect/token` with `grant_type=urn:openid:params:grant-type:ciba` |

When `Sufficit:Identity:Ciba:Enabled` is on, discovery publishes the grant in
`grant_types_supported`, `backchannel_authentication_endpoint`,
`backchannel_token_delivery_modes_supported=["poll"]` and
`backchannel_user_code_parameter_supported=false`.

## Supported mode

**Poll** only. `ping` and `push` are not implemented.

| Requirement | § | Status |
|---|---|---|
| Opaque `auth_req_id` | 7.3 | Yes |
| `expires_in` and `interval` in the response | 7.3 | Yes, from `CibaOptions` |
| `login_hint` resolving the user | 7.1 | Yes, email or username |
| `binding_message` shown before approval | 7.1 | Yes, limited to 180 characters |
| `authorization_pending` / `slow_down` | 11 | Yes |
| `expired_token` / `access_denied` | 11 | Yes |
| Per-client scope permission checked | 7.1 | Yes |
| Client eligibility policy | — | Yes, `ICibaClientPolicy` with `Observe` mode reported by the posture check |
| Polling at the token endpoint | 10.1 | Yes |
| `user_code` | 7.1 | No |
| `id_token_hint` as identifier | 7.1 | No |
| `ping` / `push` mode | 10.2, 10.3 | No |

## Client authentication

Polling goes through the token endpoint, so every client authentication method
the server accepts applies (client_secret_basic, client_secret_post,
private_key_jwt, mTLS), as do DPoP binding and the grant-type permission
`gt:urn:openid:params:grant-type:ciba`. The token endpoint enforces that
permission even when `ClientPolicyMode` is `Observe`; the eligibility policy
still runs on top of it.

The initiation endpoint is not a token endpoint: it still authenticates the
client itself, with the client secret from the form body. `private_key_jwt`
and mTLS at `/bc-authorize` are not implemented.

## Token issuance

Tokens come from the regular token pipeline (same format, lifetime, audiences,
introspection and revocation as other grants). `offline_access` is dropped, so
no refresh token is issued.

## Tests

`CibaTests`.
