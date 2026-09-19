# Account enumeration, legacy grants and a default interface method

Plan: `PLAN-IDENTITY.md` section A6, delivered in full and removed from it.
Three defects that the Fable 5 evaluation recorded as L-1, L-5 and L-6. Small
individually, and each one had survived because nothing tested for it.

## An attacker learned which accounts exist by typing anything

`SignInManager.PasswordSignInAsync` answers `LockedOut` and `NotAllowed`
**before** it verifies the password. Sign-in mapped both straight through, so
`/account/login?error=locked_out` and `error=not_allowed` were returned to
anyone who typed a username — with any password at all. A non-existent account
answers `invalid_credentials`. That difference is the enumeration: it reveals
that the account exists, and which state it is in.

Collapsing the two outcomes unconditionally would have been the obvious fix and
the wrong one: a genuinely locked-out user then has no idea why they cannot get
in, and support absorbs the cost. The rule used instead is that **the state is
disclosed to whoever proves they hold the password, and to nobody else** —
someone holding the password already knows the account exists, so the reason
tells them nothing new.

`WithoutEnumerationAsync` does that with `UserManager.CheckPasswordAsync`, which
verifies the hash without touching the lockout counter, so it cannot extend a
lockout or become its own oracle. It costs one hash on exactly the path where
the sign-in manager skipped one, which incidentally makes the two refusals take
comparable time instead of the locked-out one returning noticeably early.

## The client validator advertised two grants the server does not want

`ClientDefinitionValidator` listed `implicit` and `password` — with their
`gt:` forms — among the supported grant types. Any of the three client
definition entry points would accept a client asking for them, and the runtime
would refuse it later, or not, depending on configuration the validator could
not see.

`implicit` is gone from OAuth 2.1 and from this server: it is now rejected
outright, with no way to turn it back on. `password` is still available to the
deployments that need it, and is now gated on the same switch the runtime
honours, `LegacyGrants:Password`.

The validator lives in `Application.Abstractions` and cannot read STS options,
so the decision reaches it through a one-property `ILegacyGrantAvailability`
that the STS registers from `SufficitIdentityOptions.LegacyGrants`. Absent —
which is what Management and the manifest validator's own fallbacks get — the
answer is no. A legacy grant is not accepted anywhere nobody deliberately
enabled it.

## A default interface method that dropped its argument

`IIdentityUserSessionRevoker.RevokeAsync(subject, exceptBrowserSessionId, ct)`
carried a default body forwarding to the two-argument overload, discarding
`exceptBrowserSessionId` on the way. An implementation that did not override it
signed the caller out of the session it had just asked to keep — silently, and
only at runtime.

`CredentialMutationSecurityCoordinator` is that caller: it revokes everything
except the current session across a password change, precisely so the user is
not thrown out of the browser they are changing their password in. The
production implementation does override the overload, so production was never
affected. The test double `RetryingSessionRevoker` did not — so
`PasswordResetRevocationTests` had been exercising the discarding path and
passing.

The member is abstract now, which turns the whole class of mistake into a
compile error, and both test doubles were given the real behaviour.

## Verification

1,417 tests pass, Release build warning-clean. Each fix ships with a test that
fails without it, and that was checked by reverting each fix in turn rather
than assumed:

- `Password_sign_in_hides_account_state_from_a_wrong_password` — reverted, it
  reports `Expected: Failed / Actual: LockedOut`.
- `Shared_validator_never_accepts_the_implicit_grant` and
  `Shared_validator_gates_the_password_grant_on_the_deployment` — reverted,
  both report `Expected: False / Actual: True`.
- L-6 needs no runtime test: the compiler now rejects the omission, and the
  two doubles that had to be corrected are the evidence it was real.

## Two documentation gates found on the way

Consolidating the twelve plans had left `docs/plans/PLAN.md`, and sixteen
activities linking to plans that no longer existed. `DocumentationContractTests`
catches both, and was right on both counts:

- `Documentation_names_express_their_purpose` requires `PREFIX-NAME.md`, so the
  file is `PLAN-IDENTITY.md`.
- `Canonical_documentation_links_resolve` requires every markdown link to
  resolve. The earlier assumption that a dangling link to a retired plan was
  the repository's convention was wrong — the convention is a plain backtick
  citation, which the older activities referencing `PLAN-ROADMAP.md` and
  `PLAN-LEGACY-CUTOVER.md` already used. The sixteen links are citations now,
  marked `(retired)`.
