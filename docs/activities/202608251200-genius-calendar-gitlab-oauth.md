# Genius integration OAuth: Calendar scopes and central GitLab client

Issues:

- Identity [#45](https://github.com/sufficit/sufficit-identity/issues/45)
- Genius [#280](https://github.com/sufficit/sufficit-ai-genius/issues/280)

The subject-bound integration broker now requests the Google Calendar scopes
needed by Genius alongside Gmail and Docs. A stored Google grant that does not
contain every required scope is reported as disconnected and access returns
`authorization_required`, so the app starts the normal provider flow again
instead of failing a Calendar tool later.

The initial GitLab dynamic-registration implementation was rejected after the
full physical-device flow. GitLab.com's `/oauth/register` created an MCP-only
application even when the registration and authorization requests contained
only `api`. The provider therefore returned a grant that could not call the
stable REST API. Identity now uses one centrally managed confidential OAuth
application, requests `api`, adds PKCE, and keeps its client credentials only in
the deployment secret boundary. User access and refresh tokens remain encrypted
and subject-bound in each user's personal Vault.

The `api` scope lets Genius use GitLab's stable REST API even when
`/api/v4/mcp` returns the documented eligibility 404 for accounts without an
enabled top-level group. Existing `mcp`-only grants are reported as incomplete
and go through the normal provider authorization flow once; no PAT is requested.

Evidence:

- GitLab production DCR returned HTTP 201 but the resulting application exposed
  only the `mcp` scope, proving it unusable for the REST fallback;
- the central application callback is `https://identity.sufficit.com.br/signin-gitlab`;
- focused and complete-suite counts are recorded by the release validation.
