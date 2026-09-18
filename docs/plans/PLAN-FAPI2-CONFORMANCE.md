# FAPI 2.0 conformance plan — remaining work

The OpenID conformance harness (`conformance/`) already runs the FAPI 2.0
Security Profile plan against a disposable environment:

```bash
conformance/run.sh \
  "fapi2-security-profile-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=dpop][openid=openid_connect][fapi_profile=plain_fapi]" \
  config/fapi2.template.json
```

The environment it needs is in place: clients authenticate with
`private_key_jwt` against keys the seeder generates and registers, DPoP and the
FAPI 2 profile are on, and the pushed-request lifetime is shortened so the
expiry module fits inside the runner's budget.

**Status of the last run: 56 modules — 39 passed, 2 failed, 10 review, 3
skipped, 2 warnings.** Only the OpenID Connect Basic plan is a nightly gate
(`.github/workflows/conformance.yml`); FAPI 2 becomes one when the two
failures below are closed and the warnings are either fixed or written into
`config/fapi2.expected-failures.json` with a reason.

## What still fails

### 1. `user-rejects-authentication` (harness)

The module needs the user to deny the request and the error to come back as
`access_denied`. The conformance clients are seeded with implicit consent, so
no consent page is ever shown. It needs a client with explicit consent plus a
browser task that clicks the denial — the consent page is already automated
nowhere else, so this is new harness work, not a server change.

### 2. `ensure-pkce-code-verifier-required` (decide)

A token request that omits `code_verifier` is answered `invalid_request`; the
suite expects `invalid_grant`, reading RFC 7636 section 4.6 as covering the
missing verifier and not only a wrong one. OpenIddict raises the error before
the code is read, so the server cannot tell "no PKCE was ever used" from "the
verifier is missing" at that point. Either a handler decides it earlier from
the client's PKCE requirement, or the divergence is accepted in writing.

## Warnings left

- `CheckForUnexpectedParametersInServerMetadata`: the discovery document
  carries properties the suite does not know. The list has to be read from the
  module log and each one justified or removed.
- `EnsureIdTokenDoesNotContainNonRequestedClaims`: OpenIddict's `oi_tkn_id` and
  `oi_au_id`, the same ones accepted in the Basic plan
  (`config/oidcc-basic.expected-failures.json` says why).

## Environment

Recorded in `conformance/README.md`: the FAPI 2 run signs with a throwaway EC
certificate (the profile does not accept the RS256 of the development one),
turns the profile and DPoP on, shortens the pushed-request lifetime so the
expiry module fits the runner's budget, and restricts the TLS of the issuer
front to the BCP 195 suites the profile checks.

## What the plan already proved

Defects the repository's own tests did not cover, found here and fixed with
regression tests:

- `private_key_jwt` assertions with the ordinary `typ: JWT` were refused
  (`ClientAuthentication/StandardClientAssertionType.cs`).
- A DPoP proof sent with a pushed authorization request did not bind the code
  (`Dpop/DpopPushedAuthorizationBinding.cs`), and the profile demanded a
  `dpop_jkt` parameter RFC 9449 makes optional.
- DPoP proofs without `exp` were refused, though RFC 9449 4.2 does not require
  it; and `htu` was compared without dropping the query and the fragment or
  folding the case of the scheme and host (RFC 9449 4.3).
- A DPoP proof whose `jwk` header carried the private key was accepted.
- An elliptic-curve signing certificate could not be configured at all: the
  server threw at startup, and the Data Protection key ring cannot be wrapped
  with such a certificate either.
- A client assertion naming the wrong audience, or dated far in the future, was
  refused as `invalid_grant`/`invalid_token` — a failure to authenticate the
  client is `invalid_client` (RFC 6749 5.2).
- An access token was accepted in the query string of UserInfo (RFC 6750 2.3).
