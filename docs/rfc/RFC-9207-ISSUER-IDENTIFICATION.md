# RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **A — Complete** |
| Origin | OpenIddict (parameter), in-house (advertisement) |
| Spec | https://www.rfc-editor.org/rfc/rfc9207 |

## Implementation

OpenIddict attaches `iss` to every redirectable authorization response. The
repository adds the corresponding capability bit to the discovery document,
unconditionally:

```
context.Metadata["authorization_response_iss_parameter_supported"] =
    JsonValue.Create(true);
```

`src/sts/OpenIddictServerConfiguration.cs:567-570`.

## Why it matters

Without `iss`, a client talking to several ASs could be tricked into sending
an authorization code issued by AS A to AS B's token endpoint — the mix-up
attack from RFC 9700 §4.4. With `iss` in the response and the client
comparing it against the registered issuer, the attack fails.

The MCP authorization spec requires that an AS issuing `iss` **also**
advertise `authorization_response_iss_parameter_supported: true`; an MCP
client rejects the response if the metadata says `true` but `iss` is
missing. Since here the value is always `true` and OpenIddict always attaches
it, the two ends match.

## Dependency

The `iss` value issued is the effective issuer. If `Sufficit:Identity:Issuer`
is empty, OpenIddict derives it from the request's `Host` — and then `iss`
follows a header that could have been forged, voiding the protection.
**Configuring the issuer in production is not optional.**

## Tests

`DiscoveryTests`, `AuthorizationCodeFlowTests`.
