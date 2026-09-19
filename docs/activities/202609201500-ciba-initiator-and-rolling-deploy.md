# CIBA: who may start one, and what happens mid-deploy

Plan: `PLAN-IDENTITY.md` section B5, the test item. The refusals existed; two
of them had nothing holding them in place.

CIBA has no browser at the initiator. Whoever posts to `/bc-authorize` is
asking the server to interrupt a person on their own device, so who may do it
matters more than in a flow where the user is already present and watching.

## The two that were untested

**An initiator that did not authenticate.** A request naming no client is
refused as `invalid_request` — nothing was claimed, so nothing failed to
authenticate — and one naming a real client with the wrong secret is
`invalid_client` at 401, which is RFC 6749 5.2.

**A public client.** It keeps no secret, so nothing distinguishes it from
whoever copied its `client_id` out of a redirect URL. It authenticates as far
as it can, and the eligibility policy then refuses it as `unauthorized_client`.

Both assertions were written against what the refusal *should* be and both were
wrong on the first run — the server refuses in shapes better than the ones
guessed: `invalid_request` rather than `invalid_client` for the anonymous case,
401 rather than 400 for the public one. The tests now assert the server's
shapes, with the reason each one is right written beside it.

## Mid-deploy

`RollingCibaPendingRequestStore` imports a request it finds in the distributed
cache into the database before reading it. That exists because during a rolling
deployment a replica on the previous release creates the request in the cache
alone, the user approves, and the poll can land on an upgraded replica that
reads the database — where, without the import, the approval is invisible and
the flow hangs until the request expires.

The test creates a request through the legacy store directly, then drives find,
approve and the one-shot consume through the rolling one, and asserts the second
consume fails. Disabling the import fails it.

1,515 tests pass, Release warning-clean.
