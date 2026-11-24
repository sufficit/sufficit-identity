# Add a scope to an existing OAuth client

1. Complete — add an audited and versioned scope operation that preserves
   the complete OAuth client configuration. Validate permissions, exact
   configuration preservation, replay and stale writes.
2. Complete — run Release tests and push to main.
3. Complete — publish to the Identity cluster and verify the public endpoint.
4. Blocked pending a fresh operator token — use delegated management authorization to grant the requested
   scope, verify the client and activate the consumer.

Local Release validation covered the API contract and the scope grant policy.
The regression fixture preserves a pre-existing administrative scope, PAR
endpoint permission without a PAR requirement, PKCE and callback URLs. The
same fixture verifies idempotent replay, stale write rejection and rejection
of a newly requested reserved scope.

Release `20261124T152335Z-cc3a967` was published one node at a time without
a schema migration. All three nodes reported the exact revision
`cc3a96746c123a4c5adb73d521c93f03429b0875`, healthy readiness and the same
certificate and JWKS digests. The public route advertised PUT and rejected
an unauthenticated PUT with 401. The previous delegated token had already
expired before deployment. The production scope grant remains pending.

The full local test project passed 2,186 tests, with 20 skipped by their
environment requirements.
