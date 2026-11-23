# Access token format by audience

1. Complete — reproduced an opaque access token with the correct granted audience after device authorization.
2. Complete — select the format from the prepared access token audiences. The regression test failed before the fix and passed afterward. All 10 targeted tests passed and the Release solution build passed.
3. Pending — roll out the issuer change and verify that an operator can read the resource API with a newly approved device grant.

OpenIddict 7.8.0 filters private resource claims when preparing the access token and copies the authorized resources into its audiences. The existing per-resource format rule was consequently skipped. Client-specific rules and the default reference-token policy remain fallback choices. The integration test uses a real local authorization, approval, token redemption and introspection.
