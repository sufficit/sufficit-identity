# The ceremony moved in front of the token

Plan: `PLAN-IDENTITY.md` section A4. Owner's call, 2026-09-20: turn the
step-up on at `/authorize`, globally, at once.

A session whose second factor came from a trusted-device cookie now runs the
ceremony before an authorization request produces anything. The rule lives in
`AuthorizationReauthenticationPolicy` beside `max_age` and `prompt=login`, and
the receipt those two already use is what stops the request from bouncing.

## Why here and not in the apps

The loop that made this risky is the relying party discovering the token is
insufficient: it rejects, redirects to `/authorize` without `prompt=login`, and
gets the same session and the same token, forever. Nothing on the app side
breaks that cycle without changing the app.

The server already owned the ceremony, so it steps the session up first. The
token is honest by construction, the relying party never sees an insufficient
one, and no app changed. The ceremony signs the remembered cookie out and asks
for the factor, so the session that comes back is fresh and the next pass
through the policy does nothing — which the integration test asserts as its
second half, because that half is the proof there is no loop.

What this costs: on a remembered device, the first authorization of a session
asks for the factor once. The remembered cookie still spares the operator
inside Identity's own surfaces, which is what `9957d6d` protected.

## A defect in yesterday's delivery, found by this test

`202609200800` added `identity:mfa_remembered` to the session and refused
credential minting when it was present. Its tests built principals by hand and
passed. They were testing a claim that production would never have had.

The security-stamp validator rebuilds the principal on renewal and carries over
an **explicit list** of claim types — `sid`, `amr`, `auth_time`, `aal`, `acr` —
dropping everything else. The mark was dropped on the first renewal, so the
refusal at the token mint would never have fired, and the step-up added here
would not have either.

Found by asking the running server what the session actually carried, through a
test-only endpoint that dumps the principal, rather than by reasoning about it.
The claim type is on the carry-over list now, and the integration test asserts
the mark survives the round trip before it asserts anything else.

## Verification

1,500 tests pass, Release warning-clean. The end-to-end test signs in with a
remembered factor, asserts the mark survived, asserts a plain authorization
request — no `prompt`, no `max_age`, nothing that would otherwise challenge it
— is sent to `/account/reauthenticate`, completes the TOTP, and then asserts
the same request goes through to the client with a code and no error.

The first draft of that test used the file's existing URL helper, which
hardcodes `prompt=login`: it would have passed without any of this work. It
builds its own plain request now.
