# Integration OAuth broker

Sufficit Identity brokers third-party OAuth for trusted Genius integrations so
an end user never handles access tokens, client secrets, or provider project
configuration.

## Boundary

The API under `/api/integrations/oauth` uses two authorization boundaries:

- `status`, `authorize`, `access`, and `disconnect` require the
  `sufficit-identity-mcp` policy (`identity.mcp` scope). Their authenticated
  `sub` is the only selector for personal Vault storage.
- `start` and `callback` are browser endpoints. They accept only a 15-minute
  Data Protection ticket bound to `sub`, provider, and a random nonce. They do
  not accept bearer tokens or caller-selected Vault contexts.

Pending flow material is encrypted under
`integrations/oauth/pending/<nonce>` in `user-<sub>`. Final provider tokens are
encrypted under `integrations/oauth/tokens/<provider>` in the same context.
Callback URLs and logs never carry provider or Sufficit tokens.

## Providers

- **Google Workspace** reuses the Google external provider app already managed
  by Identity. The broker requests offline access and explicit consent for
  the scopes needed by all eight official Workspace MCP services (Gmail,
  Drive, Docs, Sheets, Slides, Calendar, Chat and People), then moves the
  external-cookie tokens into the personal Vault. `ProjectId` supplies
  `X-Goog-User-Project` to the official Workspace MCP endpoints. Stored grants
  missing any newly required scope are marked disconnected so the next normal
  connect action renews them.
- **GitHub** follows the same static-provider flow when a central GitHub OAuth
  app is enabled. Without that app the API reports `available=false`; clients
  must not offer a PAT fallback.
- **GitLab** uses a central confidential OAuth application owned by Identity,
  requests only `api`, and applies PKCE in addition to client authentication.
  GitLab.com's advertised Dynamic Client Registration endpoint is unsuitable
  for this REST integration: physical-device validation showed that it creates
  an MCP-only application even when registration requests only `api`. The
  central client credentials remain in the server secret boundary; each user
  token remains isolated in that user's personal Vault.

The `/access` endpoint refreshes an expiring provider token server-side and
returns only the HTTP headers needed by the authenticated Genius transport.
Provider client secrets never leave Identity.

## Return contract

The only native return is
`sufficit-genius://auth-complete?integration=<provider>&status=<status>`.
Identity does not accept a caller-supplied return URL. This removes an open
redirect boundary and lets Android/iOS resume the app without putting tokens in
the custom URI.
