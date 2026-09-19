# Measuring who authorizes from a remembered device

Follow-on to [`202609200800-remembered-second-factor.md`](202609200800-remembered-second-factor.md).

A token issued to an ordinary relying party still carries `amr=mfa` when the
second factor came from a trusted-device cookie. Making that honest is a
separate decision, and the obstacle to taking it was not the code: it was not
knowing which relying parties check `amr`, and what would happen to them.

Reading their source would not answer it. What matters is which clients
actually authorize from a remembered session, and only production knows that.

The authorization endpoint now records it: an `Information` log with the
`client_id`, and the `token_issuance_second_factor` counter in Observe. The
client id stays out of the metric tags — that meter is deliberately
low-cardinality and PII-free — and goes in the log, where it belongs.

Nothing is refused. This changes no behaviour for any client.

## Why the enforcement, when it comes, belongs here

The loop that makes this risky is the relying party discovering the token is
insufficient: it rejects, redirects to `/authorize` without `prompt=login`, and
the server hands back the same session and the same token, forever.

The server already owns the ceremony — `AuthorizationReauthenticationPolicy`
plus the authentication receipt — so it can step the session up *before* the
token exists. Then the token is honest by construction, the relying party never
sees an insufficient one, and no app changes. `acr_values` is ignored today;
honouring it would additionally serve the apps that do ask.

1,497 tests pass, Release warning-clean.
