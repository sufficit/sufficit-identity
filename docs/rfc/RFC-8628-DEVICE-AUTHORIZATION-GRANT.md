# RFC 8628 — OAuth 2.0 Device Authorization Grant

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **A — Complete** |
| Origin | OpenIddict, with an in-house verification controller and replay guard |
| Spec | https://www.rfc-editor.org/rfc/rfc8628 |

## Endpoints

| Role | Path | Registration |
|---|---|---|
| Device authorization (§3.1) | `/connect/deviceauthorization` | `src/sts/OpenIddictServerConfiguration.cs:49` |
| End-user verification (§3.3) | `/connect/device` | `src/sts/OpenIddictServerConfiguration.cs:50` |
| Token, `grant_type=device_code` | `/connect/token` | `DeviceCodeGrantHandler` |

`src/sts/Controllers/DeviceController.cs` serves the verification page
(`GET /connect/device`, `:150`) and processes the approval
(`POST /connect/device`, `:289`) with server-side antiforgery validation.

## Device code replay guard

`src/sts/Tokens/DeviceCodeReplayGuard.cs` (`RejectRedeemedDeviceCodeReplay`,
registered in `src/sts/OpenIddictServerConfiguration.cs:257`).

The problem: the client polls. Two concurrent requests may present the same
`device_code`. OpenIddict's native theft-detection heuristic would interpret
this as reuse and **revoke every token issued under that authorization** —
including the ones just issued to the winner of the race, whose `userinfo`
call would then start returning 401. The handler converts that case into a
plain `invalid_grant`, which is what §3.5 requires.

## Anonymous information endpoint

`GET /connect/device/info` (`DeviceController.cs:231-234`) returns client
data for the confirmation screen based on the `user_code`. Because it is
anonymous and enumerable, it has **its own rate-limit bucket**: 12 requests
per minute per IP (`src/sts/Options/RateLimitOptions.cs:57-59`), separate
from the others so that an enumeration attempt cannot drain the credential
quota.

## Requirements

| Requirement | § | Status |
|---|---|---|
| `device_code`, `user_code`, `verification_uri`, `expires_in`, `interval` | 3.2 | Yes (OpenIddict) |
| `authorization_pending` while not approved | 3.5 | Yes, `DeviceCodeGrantHandler` |
| `slow_down` on aggressive polling | 3.5 | Yes (OpenIddict) |
| `expired_token` and `access_denied` | 3.5 | Yes |
| `user_code` with adequate entropy | 5.1 | Yes (OpenIddict) |
| Brute-force attempt limit on `user_code` | 5.2 | Yes, via the `interactive` bucket and the `device/info` bucket |
| User status revalidated at issuance | — | Yes: `CanSignInAsync` and claims rebuilt from current state |

## Closing out in the browser

After approval, the browser needs to close or return control to the app.
This uses a protected ticket instead of a query-string URI
(`DataProtectionDeviceCloseFallbackTicketService`,
`DeviceFlowCloseReportController`), the same pattern as
[RFC-8252-NATIVE-APPS.md](RFC-8252-NATIVE-APPS.md).

## Tests

`DeviceFlowTests`, `DeviceFlowCloseFallbackTests`, `DeviceFlowCloseReportTests`,
`DeviceBrowserLaunchTests`.
