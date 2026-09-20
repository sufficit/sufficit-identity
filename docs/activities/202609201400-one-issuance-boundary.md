# Two issuance boundaries, both closed; the third was never open

Plan: `PLAN-IDENTITY.md` section B1, rewritten rather than ticked.

B1 came from the 2026-08-07 evaluation and asked for an `ITokenIssuanceService`
shared by the grants, personal tokens and CIBA, because "PAT, CIBA and the
OpenIddict grants still mint tokens through parallel paths". Reading the code
first — the lesson from A1, where a plan item asked for a symbol a product
decision had deliberately removed — showed most of that had already happened.

## What the plan asked for and the code already did

| Asked | Where it already was |
|---|---|
| Extract the grant handlers, leave the routes as adapters | `Exchange()` is three lines into `TokenGrantDispatcher`; all seven grants are `ITokenGrantHandler` |
| Move CIBA into the kernel and the standard boundary, keeping atomic consumption | `CibaGrantHandler` builds its identity through `GrantOperations`, returns `SignInResult`, and `TryConsumeApproved` still closes the double-poll window |
| Centralize subject rehydration, destinations, resources, sender constraint | `GrantOperations.BuildIdentityAsync`, `GetDestinations`, `ResolveResourcesAsync`, `ApplyDpopBinding` |

A2 and A3 had already done this. The item read as open because nothing named
`ITokenIssuanceService` exists — and, as with A1, absence of a symbol is not
evidence of absent work.

## What was actually still duplicated

**Personal tokens carried their own copy of the token shape.** The minting
service stamped scopes, the public `scope` claim, resources, `aud`, lifetime,
issuer metadata and destinations for provisioning and operator tokens;
`PersonalTokensController` stamped the same seven things itself, a few files
away, because it builds its identity from live user state and no flat mint
request expresses that.

`ApplyScaffoldingAsync` is that one place now, and `MintAsync` is its first
caller. Personal tokens keep what is theirs: the issuance decision, the
attenuated scopes, the lifetime bounds, the issuer error contract, and
destinations narrower than the default, because a personal token releases a
profile claim only when the matching scope was granted.

Scaffolding claims now win over whatever the caller left on the identity. No
current caller sets a stale `scope`, `aud` or issuer — the reorder is
behaviour-neutral today — but the invariant is the point: an identity copied
from an earlier decision cannot carry its old audience into a new token.

**Nothing made claim destinations mandatory.** Seven handlers ended with the
same two steps: stamp destinations, build a `SignInResult`. A grant that
skipped the first would still sign in and still mint a token, and that token
would carry no claim at all — a claim with no destination reaches nothing. The
step was mandatory in practice and optional in the type system.

`GrantOperations.SignIn` is now the only way a grant returns.

The `SetScopes` / `SetResources` / `ApplyDpopBinding` lines stayed in the
handlers. They look like duplication and are not: token exchange intersects
delegated and subject resources, the assertion grant filters by asserted
resources, the refresh branch preserves the original DPoP binding rather than
rebinding. Collapsing those into a parameterized helper would move policy into
flags.

**Issuance had no uniform record.** Personal tokens reported a policy
decision, provisioning tokens only their failures, operator tokens a line of
their own, and grants nothing. Two counters now: one per privileged token that
exists, one per grant that authorized issuance. They stay separate because
they count different events — a mint produces one reference token, a grant
produces an access token, an id token and possibly a refresh token. Subject,
client and token identifiers stay in the log lines; as metric tags they would
make both instruments unbounded.

## A test that proved nothing

The first destinations test drove a password grant and introspected the
resulting token, asserting it carried `sub` and `scope`. It passed with
`SetDestinations` deleted from the boundary: introspection answers from the
persisted token entry, so it never sees what destinations decided. The test now
asserts the principal `SignIn` returns. Deleting the line fails it.

## What is left, and why it is a decision rather than a task

A single `ITokenIssuanceService` spanning both boundaries would be a union of
two shapes, not one shape: a grant signs in through OpenIddict's pipeline and
gets a token set, while a privileged mint dispatches `GenerateTokenContext`
directly for one reference token. The remaining B1 item is to answer that in
writing either way, not to build it because a plan written before A2 and A3
assumed a duplication that no longer exists.
