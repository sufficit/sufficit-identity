# Native return URIs

## Why this exists

After a browser-side grant completes, a native client that is polling in the
background needs to be brought back to the foreground. The link that does that
is a *native return URI*. It is not a redirection endpoint: it carries no
authorization code, no token, no account and no authorization state. The client
still redeems credentials only through its own protocol flow (RFC 8628 polling
for the device grant).

Because it is still a URL this server sends a browser to, it has to be
constrained — otherwise the completion page is an open redirect.

## The rule

**The set of acceptable callbacks is per-client registration data. This server
carries no built-in list and names no application.**

That is the same rule OAuth already applies to redirection endpoints
(RFC 6749, section 3.1.2.2), and the comparison is a simple exact string match
(RFC 8252, section 8.1) — no prefix, suffix or wildcard matching. Private-use
URI schemes such as `example-app://auth-complete` are accepted here, and only
here, because RFC 8252 section 7.1 defines them as the native-app mechanism and
because nothing sensitive travels in the URI.

Storage is the `native_return_uris` extension client metadata (RFC 7591,
section 2), kept in the client record's property bag under
`identity:client:native-return-uris`.

| Concern | Where |
| --- | --- |
| Shape rules (schemes, fragments, length) | `NativeReturnUriPolicy` (Application.Abstractions) |
| Reading a client's registrations | `IClientNativeReturnUriResolver` |
| Carrying a validated value across redirects | `INativeReturnUriTicketService` |
| Registering values | Management API, provisioning manifest, management UI |

### What the policy refuses

- Anything without an explicit scheme, or that is not an absolute URI.
- `javascript:`, `data:`, `vbscript:`, `file:`, `blob:`, `about:`,
  `view-source:` — these execute in the browser or read local state.
- Plain `http` outside loopback (`https` and loopback `http` are fine; a
  browser-hosted or CLI client legitimately returns to itself).
- Fragments, whitespace, control characters, values past 512 characters.
- More than 8 registrations per client.

## How a value travels

```
native app ──(return_uri=…)──▶ GET ~/connect/device
                                 │ resolve against THIS client's registration
                                 ▼
                          /device?…&launch_mode=app&return_ticket=<encrypted>
                                 │ user approves
                                 ▼
                          POST ~/connect/device  (return_ticket posted back)
                                 │ unprotect, then resolve again
                                 ▼
                          /device?result=approved&launch_mode=app&return_ticket=<encrypted>
```

The confirmation page never sees a raw `return_uri`. It receives a ticket the
server minted with data protection (10-minute lifetime) and simply opens it, so
a query string edited in the browser resolves to nothing and the page falls back
to the neutral "you can close this tab" ending.

The result page is reached after the grant, when the device transaction is gone
and the client can no longer be looked up — which is exactly why the decision is
carried in a server-minted ticket instead of being re-checked there.

The integration OAuth broker (`/api/integrations/oauth/...`) resolves the
callback once, against the client the presented access token was issued to, and
keeps it in server-side state plus the encrypted flow ticket for the rest of the
exchange.

## Registering callbacks

**Management API** — `nativeReturnUris` on `POST /api/clients` and
`PUT /api/clients/{clientId}`. On update, omitting the field leaves the current
registration untouched; sending `[]` clears it.

```jsonc
{
  "clientId": "example-app",
  "redirectUris": ["https://app.example.com/callback"],
  "nativeReturnUris": ["example-app://auth-complete"]
}
```

**Management UI** — *Clientes → editar → Destinos e logout → Retornos nativos*,
one URI per line. The client-creation wizard does not expose the field yet; a
new client registers its callbacks on the edit screen.

**Provisioning manifest** — `nativeReturnUris` on a client entry, alongside
`redirectUris`.

## Migration

Before this change the server hard-coded two callbacks
(`sufficit-genius://auth-complete`, `sufficit-aigenius://auth-complete`) and
accepted them for any client. They are now registration data like any other, so
an existing deployment must register them on the client that uses them, e.g.:

```bash
curl -sS -X PUT "$IDENTITY/api/clients/sufficit-ai-genius" \
  -H "authorization: Bearer $OPERATOR_TOKEN" \
  -H "content-type: application/json" \
  -d '{ "...": "existing fields, plus:",
        "nativeReturnUris": ["sufficit-genius://auth-complete",
                             "sufficit-aigenius://auth-complete"] }'
```

Until that registration exists, the device page ends on the neutral close-tab
screen and `POST /api/integrations/oauth/{provider}/authorize` answers
`400 return_uri_not_registered`.

The same applies to `Sufficit:Identity:Mcp:ImplicitClientIds`, which no longer
has a built-in default and ships empty in `appsettings.json.template`: which
clients a deployment trusts with implicit `identity.mcp` is stated in that
deployment's own (ungitted) `appsettings.json`.
