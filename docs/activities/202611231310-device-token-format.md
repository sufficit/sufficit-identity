# Access token format by audience

1. Complete — reproduced an opaque access token with the correct granted audience after device authorization.
2. Complete — select the format from the prepared access token audiences. The regression test failed before the fix and passed afterward. All 10 targeted tests passed and the Release solution build passed.
3. Complete — deployed revision 48becb9c to all three production nodes on 2026-11-23. The cluster verified identical revisions, certificate and JWKS digests, and healthy liveness and readiness endpoints.
4. Complete — a fresh operator device grant returned HTTP 200 and a three-segment access token. The protected device command catalog accepted it and returned HTTP 200 with check-sync and reboot. Verification used a single read request.

OpenIddict 7.8.0 filters private resource claims when preparing the access token and copies the authorized resources into its audiences. The existing per-resource format rule was consequently skipped. Client-specific rules and the default reference-token policy remain fallback choices. The integration test uses a real local authorization, approval, token redemption and introspection.
