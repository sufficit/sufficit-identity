# A passkey now claims only what the ceremony proved

Plan: `PLAN-IDENTITY.md` section A5, delivered and removed from it. Recorded by
the Fable 5 evaluation as M-1.

## What was wrong

`AspNetCoreIdentityPasskeyService.SignInAsync` called

```csharp
authenticationContextAccessor.Set(new AuthenticationContextEvidence(
    ["passkey", "hwk", "mfa"], now, PhishingResistant));
```

**before** `PasskeySignInAsync`, unconditionally. Two consequences, one worse
than it first looks.

The claim was made without evidence. `amr=mfa` states that a second, different
factor was presented. A passkey proves possession; only *user verification* —
the PIN, the fingerprint, the face the authenticator checks itself — is the
second factor. An authenticator that merely confirmed somebody touched it
proved one factor, and the server said two.

And it was made before the ceremony ran, so a **failed** assertion still left
`amr=mfa` sitting in the request-scoped accessor.

## What the framework already did, and what it did not

ASP.NET Core Identity 10 defaults `IdentityPasskeyOptions.UserVerificationRequirement`
to `"required"`, so the request options handed to the authenticator were
already asking for user verification. That is why this never showed up as a
broken sign-in, and it is worth stating plainly: part (a) of the original item
was already true by default, and this change did not fix it.

What did not exist was anything connecting that request to the claim. Nothing
read the result, nothing refused an assertion that came back without user
verification, and nothing tied the two values together — so relaxing the
ceremony would have left the server still asserting `mfa`. Whether Identity
itself refuses a non-verified assertion under `"required"` is not something the
public surface states, and the server should not depend on an answer it cannot
see.

## What it does now

`IPasskeyAssurancePolicy` (abstractions) with `PasskeyAssurancePolicy` (STS)
reads the WebAuthn authenticator-data flags out of the serialized credential —
32 bytes of rpIdHash, then the flags byte, UP at `0x01` and UV at `0x04`
(WebAuthn Level 3, 6.1) — and answers three questions: what to ask the ceremony
for, whether to refuse, and what the result may claim.

- **Refuse early.** An assertion reporting no user verification is rejected
  before `PasskeySignInAsync` runs, so nothing is issued and there is no cookie
  to undo. The user is told to use their PIN, fingerprint or face.
- **Claim what happened.** `Set()` moved to after `result.Succeeded`, with the
  methods derived from the flag: `["passkey", "hwk", "mfa"]` when verified,
  `["passkey", "hwk"]` and `Loa1` when not.
- **One switch for both.** `Passkeys:RequireUserVerification` (default `true`)
  drives the ceremony's `userVerification` *and* the claim. Turning it off
  keeps sign-in working and drops `mfa`, so a policy demanding a second factor
  asks for one instead of being satisfied by a fiction.

Reading the flags before the signature is verified is not a bypass: the same
bytes are covered by the assertion signature Identity checks, so a forged flag
fails the ceremony. The early read only decides whether to refuse; the claims
are applied after success, when the bytes are known to be authentic.

## Verification

1,427 tests pass, Release warning-clean. Ten new tests, and the
service-level one was confirmed to fail without the fix by reverting it:
`Sign_in_refuses_an_assertion_that_proved_only_possession` reports
`Assert.Contains() Failure: Filter not matched in collection`.

The composition test was rewritten mid-work. It first asserted
`UserVerificationRequirement == "required"`, passed with the fix reverted, and
was therefore proving nothing — the framework default. It now asserts that the
two values move together, which is the property that did not hold before.
