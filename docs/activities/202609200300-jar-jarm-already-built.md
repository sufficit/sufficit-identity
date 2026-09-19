# JAR and JARM: the code was done, the refusals were not proven

Plan: `PLAN-IDENTITY.md` section B6, removed from it.

B6 came from the 2026-08-07 evaluation and asked for four things. Reading the
code before writing any showed three of them already built — and the fourth
only half covered.

## Already in the code

| Item | Where |
|---|---|
| `typ`, `iat`, `exp`, `jti` required; freshness; maximum lifetime | `JarExtractor.TryMergeAsync`, steps 1 and 6 |
| Replay refused atomically, per client | key `jar:<client>:<jti>`, through the database replay cache, whose `INSERT` on a primary key turns a concurrent duplicate into `DbUpdateException` |
| Replay marked only after the signature is verified | so anonymous garbage cannot reserve another client's ids |
| Structured and multi-valued parameters preserved | `TryReplaceWithSignedParameters` sets each value as a cloned `JsonElement`, so arrays and objects keep their shape |
| Canonicalization | duplicate parameter names refused; `request`/`request_uri` inside a request object refused; the outer parameter set replaced entirely rather than merged |
| JARM encrypts to the client's key, never a server-global one | `JarmClientEncryptionCredentialsResolver`, "solely from the recipient client's public JWKS", RSA and EC |
| Key rotation, feature-off | remote JWKS refreshes when a `kid` rotates; discovery advertises JAR/JARM only when enabled |

`JarmEncryptionOptions.Path` and `.Password` still exist — a server
certificate, which is exactly what the item warned against — but are already
documented as *"deprecated and ignored"*. Nothing reads them.

## What was missing: the refusals

There was one integration test for JAR: a well-formed request object, accepted,
then sent again. Its replay assertion was

```csharp
Assert.True(replay.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Redirect);
```

and it checked the reason only on the redirect branch. A second request refused
for *any* reason would have satisfied it. No test sent a request object of the
wrong type, without `iat`, `exp` or `jti`, living too long, or issued in the
future.

`JarExtractor.TryMergeAsync` reports each refusal through a callback with a
fixed description, so `JarRequestObjectRefusalTests` asserts the **reason**:
wrong `typ` (two variants), missing `iat`, missing `exp`, missing `jti`,
lifetime over the maximum, issued in the future, and replay. It runs against
the real container's application manager, key resolver and replay cache, with
two registered clients.

Two things the first draft got wrong:

- a baseline that must be *accepted*, so a harness refusing everything cannot
  pass the refusals — added before trusting any of them;
- `A_jti_is_scoped_to_its_client` used one client, so it proved replay and
  nothing about scope. It now sends the same `jti` from two clients: the second
  client is accepted, then its own repeat is refused.

## Verification

1,473 tests pass, Release warning-clean. Reverting the `typ` check and keying
the replay cache on the `jti` alone made exactly the three tests that depend on
them fail — both `typ` variants and the per-client scope — while the others
kept passing, because their checks were untouched.

JAR and JARM are both off in production, so nothing live changes; the next
person to enable them has the refusals pinned.
