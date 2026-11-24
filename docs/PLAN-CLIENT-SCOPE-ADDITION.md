# Add a scope to an existing OAuth client

1. Complete — add an audited and versioned scope operation that preserves
   the complete OAuth client configuration. Validate permissions, exact
   configuration preservation, replay and stale writes.
2. Complete — run Release tests and push to main.
3. In progress — publish to the Identity cluster and verify the public endpoint.
4. Pending — use delegated management authorization to grant the requested
   scope, verify the client and activate the consumer.

Local Release validation covered the API contract and the scope grant policy.
The regression fixture preserves a pre-existing administrative scope, PAR
endpoint permission without a PAR requirement, PKCE and callback URLs. The
same fixture verifies idempotent replay, stale write rejection and rejection
of a newly requested reserved scope.
