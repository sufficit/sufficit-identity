# SCIM enabled with nobody allowed to use it

Plan: `PLAN-IDENTITY.md` section A3, one item, delivered.

`ScimOptions.AllowedClientIds` defaults to empty, and empty is fail-closed by
design: with `RequireAllowedClient` on and the policy enforcing, every SCIM
request is refused until a provisioning client is listed. That is the right
default and not a hole.

It is also silent. A deployment that turns SCIM on and forgets the allow-list
learns about it only from 403s at the provisioning client — on the other side
of the integration, usually someone else's system.

`scim-client-allow-list-empty` reports it at startup as an **advisory**: enabled,
enforcing, and no non-blank client id. Blank entries do not count, since `"  "`
would otherwise look configured. It never blocks — blocking on a fail-closed
state would refuse to start a server whose only fault is being too strict.
Observe mode with an empty list is a different and worse state (everyone is
let through with a log line), already reported as the blocking
`scim-client-policy-observe`.

Verified: the test fails with the finding disabled and passes with it; 1,487
tests pass; Release warning-clean.
