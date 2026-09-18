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

**Status: 56 modules, exit code 0 — 42 passed, 9 review, 3 skipped, 1 warning
and 1 failure, the last two accepted in `config/fapi2.expected-*.json` with a
written reason.** The plan runs in the nightly workflow next to the Basic one.

## The one accepted failure

`par-attempt-to-use-expired-request_uri` expects the error to reach the client
as a redirect carrying `invalid_request_uri`; the server refuses the expired
`request_uri` on its own error page instead. OpenIddict drops the request while
extracting it, before any redirect URI has been resolved — the authorization
request carries only `client_id` and `request_uri` — so there is nowhere to send
the error to. No authorization is granted and the user is told.

Closing it means resolving the client's registered redirect URI before the
refusal, and only when the registration leaves no ambiguity.

**Attempted on 2026-09-18 and reverted.** A handler on
`ApplyAuthorizationResponseContext` does find the client and its single
registered URI, but nothing downstream honours what it sets:
`Authentication.AttachRedirectUri` clears a redirect URI it did not validate
itself, `InferResponseMode` derives the mode from a `response_type` this
request never had, and the local error response is produced regardless. Making
it work means reaching further into OpenIddict's authorization pipeline than
this single conformance module justifies — the error is shown to the user and
no authorization is granted either way. Revisit if a client ever needs the
machine-readable error.

## Accepted warning and skips

- `FAPIEnsureServerConfigurationDoesNotSupportRefreshToken`: the plan's clients
  never ask for `offline_access`, so no refresh token is issued and the module
  skips. Refresh tokens have their own tests.
- The `claims` request parameter is not implemented and discovery says so.
- `ensure-signed-client-assertion-with-RS256-fails` needs an RSA client key; the
  conformance clients hold EC keys.
- `EnsureIdTokenDoesNotContainNonRequestedClaims`: OpenIddict's `oi_tkn_id` and
  `oi_au_id`, accepted in the Basic plan for the same reason.

## Environment

Recorded in `conformance/README.md`: the FAPI 2 run signs with a throwaway EC
certificate (the profile does not accept the RS256 of the development one),
turns the profile, DPoP and mandatory PKCE on, seeds clients that ask for
consent on every authorization (one module has the user deny), shortens the
pushed-request lifetime so the expiry module fits the runner's budget, and
restricts the TLS of the issuer front to the BCP 195 suites the profile checks.

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
