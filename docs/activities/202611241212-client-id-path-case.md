# Case-sensitive client identifiers in management paths

1. Complete — preserve client identifiers in management API paths and add
   regression coverage for lookups and updates.
2. Complete — run Release validation and push the reviewed change to main.
3. Complete — roll out Identity one node at a time and verify the management API
   accepts the original identifier without a redirect.

The incoming path continues to pass the existing local URL validation.
OpenID Connect and account page redirects retain their existing behavior.

The two regression cases failed with HTTP 308 before the fix. Release build
passed without warnings. The middleware and Markdown checks passed (20 tests).
The main test project passed 2,184 tests, with 20 skipped by its environment
and fixture requirements.

## Production verification

Release `20261124T150506Z-e1d6901` carries revision
`e1d69017562c00bca7ca7c50cbdcb4ecfdb9ed79`. The package SHA-256 is
`3dc737131693207041e43a56427c257ad5f7068fe15933283f2eaeca05f9950f`.

The cluster wrapper activated the release one node at a time. All three nodes
reported healthy liveness and readiness, the same application certificate and
the same JWKS digest as before the rollout. This change required no schema
migration. Each node recovered from the brief HTTP 502 responses during restart.

A delegated, authenticated lookup using an ID with uppercase letters returned
HTTP 200 on the public management endpoint, with no redirect.
