# Case-sensitive client identifiers in management paths

1. Complete — preserve client identifiers in management API paths and add
   regression coverage for lookups and updates.
2. Complete — run Release validation and push the reviewed change to main.
3. Blocked pending authorization for production deployment — roll out Identity one node at a time and verify the management API
   accepts the original identifier without a redirect.

The incoming path continues to pass the existing local URL validation.
OpenID Connect and account page redirects retain their existing behavior.

The two regression cases failed with HTTP 308 before the fix. Release build
passed without warnings. The middleware and Markdown checks passed (20 tests).
The main test project passed 2,184 tests, with 20 skipped by its environment
and fixture requirements.
