# Intermittent userinfo 401 after concurrent device-code redemption (issue #61)

Date: 2026-09-09 15:09 UTC · Branch: `issue/61-userinfo-401-concurrent-device-code`

## Context

CI run [34357932338](https://github.com/sufficit/sufficit-identity/actions/runs/34357932338/job/102487240211)
failed in `DeviceFlowTests.Approving_the_device_code_lets_the_polling_client_redeem_an_access_token`
(line 343): of two final polls racing for the same `device_code`, the winner
redeemed tokens but its subsequent `/connect/userinfo` returned **401**, not 200.
Two earlier CI runs passed; the local 1068-test suite passed; four isolated
worktree runs of the single test passed. Classic interleaving-dependent flake.

## Investigation

Decompiled OpenIddict 7.6 (`OpenIddict.Server`) and traced both paths that
reject a replayed `device_code` at `/connect/token`:

1. **`Protection.RedeemTokenEntry`** (ProcessSignIn stage): the loser that
   reaches redemption *before* the winner commits loses `TryRedeemAsync` and is
   rejected with `invalid_token`/ID2011 — **no side effects**.
2. **`Protection.ValidateTokenEntry`** (ProcessAuthentication stage): the
   loser that validates *after* the winner committed finds the token entry
   with status `redeemed` and runs the **theft heuristic** (the one guarding
   refresh-token rotation): `RevokeByAuthorizationIdAsync` revokes **every
   token of the authorization** — including the reference access token (and
   refresh token) just issued to the winner — then rejects with
   `invalid_token`/ID2011.

Access tokens are reference tokens by default
(`TokenLifetimeOptions.UseReferenceAccessTokens = true`), so `/connect/userinfo`
resolves the winner's token against the database entry — which path 2 just
revoked → **401**. The intermittency is simply which of the two paths catches
the loser: arrival order decides whether the winner's tokens survive.

Proved deterministically before fixing: a sequential test (winner completes →
loser replays → winner calls userinfo) failed on `main` with
`Expected: OK / Actual: Unauthorized` — the exact CI symptom, no race needed.

## Root cause

OpenIddict's theft heuristic is correct for refresh tokens (reuse of a rotated
token IS theft evidence) but wrong for device codes: RFC 8628 clients poll on a
timer, so a racing final poll replaying the single-use `device_code` is an
*expected* protocol error by the *same authenticated client*, seconds after the
authorization was created. It must cost the loser an `invalid_grant` — and
nothing else. The cascade was destroying the legitimate winner's tokens.

## Fix

`src/sts/Tokens/DeviceCodeReplayGuard.cs` — `RejectRedeemedDeviceCodeReplay`,
a scoped `IOpenIddictServerHandler<ValidateTokenContext>` ordered at
`Protection.ValidateTokenEntry.Order - 500`:

- scope: only principals whose token type is `device_code`; everything else
  (access, refresh, authorization code, user code) keeps built-in semantics;
- if the token entry exists and is `redeemed` → `context.Reject(invalid_grant)`
  and the dispatcher stops **before** the built-in theft branch, so no
  `RevokeByAuthorizationIdAsync` cascade runs;
- entries that are valid/pending/rejected still fall through to the built-ins
  (`authorization_pending` / `access_denied` / expiry unchanged).

Registered unconditionally in `OpenIddictServerConfiguration.cs` (it is a
protocol-semantics fix, not an opt-in feature). Refresh-token replay semantics
are deliberately untouched.

## Validation

- New regression test
  `DeviceFlowTests.Replay_of_a_redeemed_device_code_keeps_the_winners_tokens_valid`
  (deterministic sequential interleaving; no `Task.WhenAll`, no timing):
  **RED on `main`** (userinfo 401) → **GREEN with the guard**.
- Target test repeated 3×/3× stable without rebuild.
- `DeviceFlowTests` 8/8; full suite **1069/1069** (main's 1068 + the new test).
- The pre-existing concurrent-race test (unchanged, still asserts exactly one
  OK + one `invalid_grant`) passes — the race is still exercised, not hidden.

## Files

- `src/sts/Tokens/DeviceCodeReplayGuard.cs` (new) — the guard handler
- `src/sts/OpenIddictServerConfiguration.cs` — registration
- `src/tests/DeviceFlowTests.cs` — deterministic regression test
