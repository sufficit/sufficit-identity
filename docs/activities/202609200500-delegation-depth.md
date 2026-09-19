# Token exchange: a delegation chain now has a bottom

Plan: `PLAN-IDENTITY.md` section B3, first item, delivered.

Each RFC 8693 exchange nests the subject token's `act` claim inside the new
one, so the token says not only who acts now but on whose behalf that actor
was acting. The RFC leaves the chain unbounded, and so did this server: every
exchange added a level. The chain grows by one object per hop — every token
larger than the last — and two services that exchange each other's tokens
never stop.

`TokenExchange:MaxDelegationDepth` (default 5) bounds it. The handler counts the
subject token's existing chain before building anything and refuses with
`invalid_grant` when one more level would exceed the bound. Five is well above
a real path — a user, a service acting for them, that service's downstream —
and far below anything that matters for token size. Values outside 1–16 refuse
startup.

A chain that cannot be read — not JSON, an `act` that is a string or an array,
nesting past the parser's own limit — now counts as one that cannot be
extended, and is refused. Before, the same token reached
`JsonSerializer.Deserialize` further down, which is where the nesting happens,
and would have thrown there.

## Verification

1,486 tests pass, Release warning-clean. The integration test was written
first and failed for the right reason before the change — the two exchanges
inside a bound of 2 succeeded with the introspected depth at 1 and then 2, and
the third returned `OK` instead of `BadRequest`. It chains real exchanges of a
client's own token rather than hand-built claims, so it proves that the depth
the handler counts is the depth the tokens actually carry. Unit tests cover the
counter on nested, empty, malformed and too-deep chains, and the startup refusal
for 0 and 17.
