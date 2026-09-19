# Six settings the production posture check was not looking at

Plan: `PLAN-IDENTITY.md` section D1, delivered and removed from it. Recorded by
the Fable 5 evaluation as A-1, which called it the highest-value architectural
item in that review, and was right: `ProductionPostureCheck` is the cheapest
mechanism this repository has for turning a configuration regression into a
deliberate, attributed, expirable decision, and its coverage had fallen behind
the configuration surface it is supposed to cover.

## The findings

| Id | Severity | Why |
|---|---|---|
| `legacy-grants-enabled` | Blocking | ROPC and the `none` response type |
| `csp-policy-permissive-source` | Blocking when enforcing, advisory in report-only | A wildcard, bare scheme or unsafe keyword in `script-src`/`connect-src` |
| `certificate-purpose-not-separated` | Advisory | One certificate file for signing and encryption |
| `token-exchange-enabled-by-default` | Advisory | RFC 8693 serving because of a default, not a decision |
| `passkey-user-verification-optional` | Advisory | Possession-only passkey sign-in |
| `access-token-unmapped-claims` | Advisory | Claims with no scope mapping released to every audience |

## Why only one of them blocks

`legacy-grants-enabled` blocks because it has already happened: ROPC was found
enabled in a configuration nobody meant to ship (evaluation 2026-08-15, H-1),
and a startup gate would have reported it at the boot that introduced it.
That is the entire argument for this pattern.

`csp-policy-permissive-source` blocks only when the policy is enforcing. In
report-only the policy blocks nothing, so a weak source is a calibration
problem rather than a live hole — and calling it blocking there would refuse
startup over a header that does not yet do anything.

The other four are advisories on purpose, and the reason differs each time:

- **`certificate-purpose-not-separated`** — production is in exactly this state
  and cannot leave it. The runtime rejects every replacement PFX generated off
  the server
  ([investigation](202608161930-pfx-encryption-cert-investigation.md)).
  Refusing startup would take the service down over a condition its operators
  already know about and cannot resolve today.
- **`passkey-user-verification-optional`** — since
  [A5](202609191700-passkey-assurance.md) the server stops claiming `amr=mfa`
  when verification is off, so the relaxation is degraded but honest.
- **`access-token-unmapped-claims`** and **`token-exchange-enabled-by-default`**
  — both are the shipped default. Blocking on a default refuses every
  deployment's first boot.

## The one finding that was rewritten mid-work

The item asked for "token exchange enabled with an empty allow-list". Built
literally, that advisory fires on **every** deployment: empty is the documented
default, and the OpenIddict per-application grant permission is already the
boundary — the allow-list is a second, optional layer. An advisory nobody can
ever clear teaches operators to skim the list, which costs more than the
finding is worth.

What has no decision behind it is the grant being *on* without anyone saying
so, which is what M-2 was actually about. The finding now fires when token
exchange is serving, has no allow-list, **and** `TokenExchange:Enabled` is
absent from configuration. Declaring the switch clears it; turning it off
clears it; leaving it to a default does not.

`access-token-unmapped-claims` was left firing on the default deliberately, and
the difference is that it can be cleared — by the claim inventory in section
B2, which is the work it exists to keep visible.

## Comparing certificates

The thumbprint comparison already exists in `IdentityCertificateMaterial`, but
only under `RequirePurposeSeparation=true`, where it throws. The posture check
runs before any certificate is loaded and has neither the passwords nor a
reason to do I/O at startup, so it compares the configured paths through
`Path.GetFullPath`, which catches the same file reached by a different
spelling. Two distinct files holding the same key are not caught — and the
operator holding two such files already knows.

## Verification

1,436 tests pass, Release warning-clean. Nine new tests; disabling the six
findings makes seven of them fail, which was checked rather than assumed.

One of those tests was wrong on the first attempt: it paired
`/etc/sufficit/identity/certificate.pfx` with `./certificate.pfx` expecting
them to normalize to the same path. `Path.GetFullPath` resolves a relative path
against the process working directory, not against the other argument, so the
test was asserting something the code never claimed. It now uses
`/etc/sufficit/identity/../identity/certificate.pfx`, which is the same file
spelled differently and is what the normalization is for.

`Certificate_key_source_and_enabled_breach_check_fail_closed_have_no_advisories`
also had to change: it asserted that a near-default configuration produces no
advisories, which stopped being true the moment the permissive defaults became
visible. It now settles them explicitly, so it asserts the absence of
advisories rather than the absence of coverage.
