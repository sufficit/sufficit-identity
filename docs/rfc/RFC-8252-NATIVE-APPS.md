# RFC 8252 — OAuth 2.0 for Native Apps

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **B — Substantial** |
| Origin | In-house (URI policy and return tickets) |
| Spec | https://www.rfc-editor.org/rfc/rfc8252 |

## Implementation

`src/management/Clients/ClientUriPolicy.cs` enforces the BCP's rules on the
registration of any client:

| Rule | § | Where |
|---|---|---|
| `https` required, except for loopback | 7.3 | `ClientUriPolicy.cs:69` |
| Private-use scheme (`com.example.app:/oauth`) accepted | 7.1 | `ClientUriPolicy.cs:85` |
| Literal redirect comparison, no normalization | 8.1 | `ClientUriPolicy.cs:86` |
| Variable port on loopback | 7.3 | Accepted, since OpenIddict's comparison handles host and path |
| Fragment forbidden in redirect | — | Yes |
| PKCE required | 8.1 | Yes, see [RFC-7636-PKCE.md](RFC-7636-PKCE.md) |

## Return path for native applications

Beyond the standard redirect, there is a dedicated mechanism for the case
where the system browser needs to hand control back to the app: a **ticket
protected by Data Protection** instead of carrying the return URI in the
query string.

| Component | Role |
|---|---|
| `src/sts/DataProtectionNativeReturnUriTicketService.cs` | Creates and resolves the opaque ticket. |
| `src/sts/OpenIddictClientNativeReturnUriResolver.cs` | Resolves the registered URI from the ticket. |
| `src/sts/DataProtectionDeviceCloseFallbackTicketService.cs` | Same pattern for closing out the device flow. |

The benefit is that the return URI never travels as a browser-manipulable
parameter, which removes that particular class of open redirect.

## Gaps

- There is no App Links / Universal Links verification (`assetlinks.json` /
  `apple-app-site-association` association); a private-use scheme registered
  by another app on the device remains an operating-system-level risk, not
  mitigable at the AS.

## Tests

`NativeReturnUriPolicyTests`, `DeviceBrowserLaunchTests`,
`DeviceFlowCloseFallbackTests`, `LocalUrlValidatorTests`.
