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
  Gmail modify, Drive, and Docs scopes, then moves the external-cookie tokens
  into the personal Vault. `ProjectId` supplies `X-Goog-User-Project` to the
  official Workspace MCP endpoints.
- **GitHub** follows the same static-provider flow when a central GitHub OAuth
  app is enabled. Without that app the API reports `available=false`; clients
  must not offer a PAT fallback.
- **GitLab** uses GitLab's advertised Dynamic Client Registration endpoint and
  PKCE. The Genius contract requests only `api`, without the MCP resource
  indicator, because the application uses GitLab's stable REST API for every
  account. Mixing the group-gated MCP resource with `api` makes GitLab issue an
  MCP-only token and leaves REST calls unauthorized. Per-user client material
  is kept only in the pending/token Vault records and participates in refresh.

The `/access` endpoint refreshes an expiring provider token server-side and
returns only the HTTP headers needed by the authenticated Genius transport.
Provider client secrets never leave Identity.

## Return contract

The only native return is
`sufficit-genius://auth-complete?integration=<provider>&status=<status>`.
Identity does not accept a caller-supplied return URL. This removes an open
redirect boundary and lets Android/iOS resume the app without putting tokens in
the custom URI.
