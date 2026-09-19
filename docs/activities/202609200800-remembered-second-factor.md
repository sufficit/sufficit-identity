# A remembered device operates Management; it does not mint credentials

Plan: `PLAN-IDENTITY.md` section A4, the decision item, resolved by the owner
on 2026-09-20 and delivered.

## The question

`9957d6d` (2026-08-14, "preserve remembered MFA sessions") projects `amr=mfa`
from the trusted-device cookie, so an operator who completed MFA on this
browser is not rejected by Management at every login. The Fable 5 evaluation
(M-8) asked for the opposite the next day, and the plan inherited the request
without noticing it reversed a deliberate fix.

The owner's answer: **it satisfies Management, it must not satisfy token
generation.**

## The distinction the code did not have

Both halves read the same `amr` claim, so nothing could tell a second factor
presented now from one remembered for up to thirty days.
`AuthenticationContextEvidence` now carries `RememberedSecondFactor`, the
session principal carries `identity:mfa_remembered`, and renewals keep it —
the evidence only exists on the request that signed in.

`MfaEvidencePolicy` in `Application.Abstractions` answers both questions:
`HasMfaEvidence` for using a session, `HasFreshMfaEvidence` for minting a
credential.

## Where it applies

A token outlives the browser that asked for it, so every path that issues one
now needs the factor from this session: operator tokens, provisioning tokens,
DCR initial access tokens and personal tokens. `ManagementOperationGuard`
gained a `mintsCredential` argument rather than a capability list, because
`ClientsCreate` both creates clients and issues initial access tokens — gating
the capability would have blocked ordinary client creation too.

The refusal is `StepUpRequired`/`fresh_mfa_required`, which sends the operator
to `/account/reauthenticate` — the ceremony that signs the remembered cookie
out and asks for the factor again. Fleet already drives token management this
way, with `prompt=login` and `max_age=0`.

A deployment that does not require MFA for Management is left alone. There is
no second factor there to insist on being fresh, and refusing would be stricter
than the deployment asked to be.

## One reading of amr, and a bug it was hiding

The method list was copied in six places. Unifying them on `MfaEvidencePolicy`
turned up a real divergence: the `MfaRequirement` authorization handler in
`management/ServiceCollectionExtensions.cs` compared **whole claim values**
against the list, without splitting on spaces. An `amr` that arrives
space-delimited — which is how it comes back from token validation, and the
reason the STS helper documents the split — never matched, so that requirement
failed for a genuinely multi-factor caller. It reads through the shared policy
now.

## What was not decided

Whether a token issued to an ordinary relying party should still carry
`amr=mfa` from a remembered device. Today it does, and no relying party's
behaviour changes here. Making it honest would mean those users are challenged
by any relying party that checks `amr` — correct, but it can loop for a client
that checks the claim without asking for `prompt=login`, so it needs its own
decision.

## Verification

1,494 tests pass, Release warning-clean. Seven new tests; disabling the rule
fails exactly the one that asserts a remembered device cannot mint. The
Management half is pinned too — a remembered device still passes an ordinary
capability demand — so the decision cannot be half-reverted by accident.
