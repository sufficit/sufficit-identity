# Genius integration OAuth broker

Issue: [#42](https://github.com/sufficit/sufficit-identity/issues/42)

Added a subject-bound third-party OAuth broker protected by `identity.mcp`.
Google Workspace reuses the configured Identity OAuth app, GitLab uses DCR and
PKCE, and GitHub advertises availability only when its central app is enabled.

Provider access and refresh tokens are encrypted in the authenticated user's
personal Vault. Browser tickets expire after 15 minutes, contain no bearer or
provider token, and return only to the Genius native URI. Access-token refresh
and Google quota-project headers are resolved on the server, so Genius never
needs a client secret or a manual token field.
