# Genius integration OAuth: Calendar scopes and GitLab public clients

Issues:

- Identity [#45](https://github.com/sufficit/sufficit-identity/issues/45)
- Genius [#280](https://github.com/sufficit/sufficit-ai-genius/issues/280)

The subject-bound integration broker now requests the Google Calendar scopes
needed by Genius alongside Gmail and Docs. A stored Google grant that does not
contain every required scope is reported as disconnected and access returns
`authorization_required`, so the app starts the normal provider flow again
instead of failing a Calendar tool later.

GitLab dynamic registration now follows its public-client contract: the broker
registers the callback, `mcp` and `api` scopes and MCP resource, uses PKCE, and accepts a
response without `client_secret`. Authorization-code and refresh requests omit
that field for the public client while confidential static providers continue
to send it. A refreshed token preserves the prior grant scope when the provider
does not repeat it.

The `api` scope lets Genius use GitLab's stable REST API when `/api/v4/mcp`
returns the documented eligibility 404 for accounts without an enabled
top-level group. Existing `mcp`-only grants are reported as incomplete and go
through the normal provider authorization flow once; no PAT is requested.

Evidence:

- GitLab production DCR returned HTTP 201 with `client_id` and no
  `client_secret` for the exact new payload;
- focused broker tests passed (6/6);
- the complete Identity test suite passed (871/871).
