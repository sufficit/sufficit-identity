# The breach check went on in production, and a node was found out of step

Plan: `PLAN-IDENTITY.md` section F11, still open for `FailClosed`.

The validator, its range cache and its local list landed on 2026-09-20. Until
today no production node ran them: `Sufficit__Identity__Password__RejectBreached`
was empty on all three, and the posture check said so on every boot.

## The switch

`security-rollout.sh` carries the gates an operator flips against a running
node, and this one was missing, so enabling the check meant editing
`hardening.env` by hand. The new `enable-breach-check [mode]` takes the failure
mode as its argument, because that is the decision a deployment actually makes:
the check calls an external service on every password creation and change, and
what happens when that call fails is the part worth choosing. An unknown mode is
refused rather than written.

`LocalFallback` is what the three nodes run. An outage of
`api.pwnedpasswords.com` then neither accepts a password from every breach
corpus nor stops password changes across the deployment: the validator answers
from its cached ranges and its local list. All three hosts reach the API in
under 100 ms, measured before the change.

Rolling, one node at a time, restart and verify between:

| Node | `RejectBreached` | Failure mode | Restarts | Ready |
|---|---|---|---|---|
| eveo-apps | true | LocalFallback | 0 | 200 |
| apoint-apps | true | LocalFallback | 0 | 200 |
| castrum-apps | true | LocalFallback | 0 | 200 |

`password-breach-check-disabled` is gone from the posture output on every node,
and `Production posture check passed` still holds.

## What the walk turned up

Reading `security-rollout.sh status` on all three before changing anything is
what exposed the real finding: **castrum-apps had JARM enabled and the other two
did not.**

That is not a harmless difference. Discovery is served by every node behind the
same hostname, so a client that reads `response_modes_supported` from castrum
learns `jwt`, `query.jwt`, `fragment.jwt` and `form_post.jwt` — and a later
authorization request carrying `response_mode=jwt` is refused by whichever of the
other two answers it. Asked directly, castrum returned all four; the public
endpoint, sampled three times, returned none, so the drift had not yet reached a
client.

JARM is built and tested but the plan itself keeps it unaudited and asks for an
external review before anything relies on it. One node advertising it to the
public pool is the side of the divergence to remove, not the side to spread, so
castrum was brought down to the other two. Its discovery now reports
`form_post, fragment, query` and no `authorization_signing_alg_values_supported`,
identical to eveo and apoint. `enable-jarm` turns it back on in one command when
the audit is done, on all three at once.

## Still advisory

- `certificate-purpose-not-separated` — one certificate signs and encrypts.
  Blocked on provisioning a dedicated encryption certificate.
- `access-token-unmapped-claims` — needs the claim inventory in B2 before
  `IncludeUnmappedClaimsInAccessTokens=false` can be set without dropping a
  claim some consumer reads.
- `scim-client-allow-list-empty` — SCIM is enabled with no allowed client, so
  every provisioning request is refused. Fail-safe, but the honest state is
  either a listed provisioning client or SCIM off.
