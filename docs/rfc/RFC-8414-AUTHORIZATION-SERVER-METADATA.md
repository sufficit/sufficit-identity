# RFC 8414 — OAuth 2.0 Authorization Server Metadata

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **A — Complete** |
| Origin | OpenIddict, with an in-house complementary handler |
| Spec | https://www.rfc-editor.org/rfc/rfc8414 |

## Implementation

The document is served at `/.well-known/openid-configuration` by OpenIddict.
An in-house handler, registered right after `AttachEndpoints`
(`src/sts/OpenIddictServerConfiguration.cs:497-640`), adds or corrects the
entries OpenIddict does not know about.

| Metadata | Source | Condition |
|---|---|---|
| `issuer`, endpoints, `scopes_supported`, `claims_supported` | OpenIddict | Always |
| `jwks_uri` | OpenIddict | Always |
| `code_challenge_methods_supported` | OpenIddict | Reflects the removal of `plain` |
| `require_pushed_authorization_requests` | OpenIddict | Follows `Par.RequireForAllClients` |
| `backchannel_logout_supported` and `_session_supported` | In-house | Publishes the dispatcher's real value |
| `frontchannel_logout_supported` and `_session_supported` | In-house | Same |
| `registration_endpoint` | In-house | Only with DCR enabled |
| `authorization_response_iss_parameter_supported` | In-house | Always `true` |
| `client_id_metadata_document_supported` | In-house | Follows the CIMD flag |
| `dpop_signing_alg_values_supported` | In-house | Only with DPoP enabled |
| `authorization_signing_alg_values_supported` | In-house | Only with JARM enabled |
| `authorization_encryption_alg/enc_values_supported` | In-house | Only with encrypted JARM |
| `request_parameter_supported`, `request_object_signing_alg_values_supported` | In-house | Only with JAR enabled |
| mTLS aliases (`mtls_endpoint_aliases`) | OpenIddict | Only with mTLS enabled |

## Guiding principle

The comment in the code states — and the code honors — that **nothing is
advertised unless it is implemented and wired up**. Capabilities that used
to be published unconditionally were removed when there was no
implementation behind them (`src/sts/OpenIddictServerConfiguration.cs:492-503`).
This matters because a client that reads `backchannel_logout_supported: true`
and never receives a `logout_token` ends up with an orphaned session.

## Issuer

`SetIssuer` is only called when `Sufficit:Identity:Issuer` is configured
(`:146-150`). Without it, OpenIddict derives the `issuer` from the request's
`Host`, which follows a potentially forged header. **Always configure it in
production.**

## Resource server discovery

Separately, `/.well-known/oauth-protected-resource` implements RFC 9728 —
see [RFC-9728-PROTECTED-RESOURCE-METADATA.md](RFC-9728-PROTECTED-RESOURCE-METADATA.md).
And `/.well-known/ssf-configuration` describes the SSF transmitter
([SPEC-SSF-CAEP-RISC.md](SPEC-SSF-CAEP-RISC.md)).

## Tests

`DiscoveryTests` — the test pins down both the presence **and the absence**
of metadata according to the flags, which prevents accidental
announcements.
