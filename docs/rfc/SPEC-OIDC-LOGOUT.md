# RP-Initiated, Front-Channel and Back-Channel Logout

| | |
|---|---|
| Role | OpenID Provider |
| Coverage | **B — Substantial** |
| Origin | Mixed |
| Specs | RP-Initiated Logout 1.0, Front-Channel Logout 1.0, Back-Channel Logout 1.0 |

## RP-Initiated Logout

`GET /connect/endsession` (and the `/connect/logout` alias) validates the
request via OpenIddict and redirects to the UI's confirmation page
(`src/sts/Controllers/AuthorizationController.Logout.cs:37-64`).

Relevant implementation detail: the intermediate step **does not** forward
`id_token_hint`. Only `post_logout_redirect_uri` and `state` go on to the UI.
The reason is recorded in the code — a JWT in the `Location` header once blew
past nginx's response buffer and turned a valid logout into a 502. The request
has already been validated by OpenIddict at that point; the UI doesn't need
the hint.

The `POST` performs the sign-out (`:66-224`) with antiforgery validated on the
server. There is one deliberate exception: if validation fails **and there is
no active session**, the request proceeds. The attack this protection exists
to prevent is forcing the logout of someone who *is* authenticated; refusing
someone who already has no session would only turn "sign out" into a protocol
error on a page the user can no longer use.

## Back-Channel Logout

Announced only when `BackchannelLogout:Enabled`
(`src/sts/OpenIddictServerConfiguration.cs:506-511`). The dispatcher
distributes a signed `logout_token` to registered RPs, with an 8-second limit
and exception capture: a slow or unavailable RP does **not** block the local
sign-out (`AuthorizationController.Logout.cs:150-170`).

| Requirement | Status |
|---|---|
| `logout_token` signed with `events` and `sid` | Yes |
| `sub` or `sid` present | Yes, both when available |
| Fan-out only to RPs with a session | Yes, resolved before sign-out |
| RP requiring `sid` is skipped when there's no `sid` | Yes (`BackchannelLogoutDistributor.cs:138`) |
| RP failure doesn't block the local sign-out | Yes |
| Retry with backoff | No |

## Front-Channel Logout

Iframe fan-out page, `GET /connect/frontchannel-logout`
(`AuthorizationController.Logout.cs:225-227`). The design point: RP URLs
**never** come from the query string. What travels is an opaque context
identifier (`logout_context`), prepared before sign-out while the subject is
still known, and resolved server-side. This removes the open-redirect class
this page normally carries.

## Side effects of signing out

| Effect | Where |
|---|---|
| Server-side session removed | `OidcUserSessionTicketStore` |
| CAEP `session-revoked` signal | `_sharedSignalsDispatcher.SessionRevokedAsync` |
| Remembered-MFA cookie discarded when `force_mfa` | `ForgetTwoFactorClientAsync` |

## Gaps

- Session Management 1.0 (`check_session_iframe`) is not implemented, by
  decision: it depends on third-party cookies, blocked by default in browsers
  today. Server-side sessions and the back-channel cover the case.
- No retry of `logout_token` for an unavailable RP.

## Tests

`BackchannelLogoutTests`, `FrontchannelLogoutTests`,
`FrontchannelLogoutReplayTests`, `ServerSideSessionsTests`.
