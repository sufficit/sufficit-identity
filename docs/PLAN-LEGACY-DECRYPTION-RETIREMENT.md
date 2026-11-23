# Legacy token decryption retirement

1. Completed. Verify the confirmed test account, public OAuth client and production device flow endpoint.
2. Completed. Obtain interactive consent from the test account, check the refresh token key identifier and verify renewal with a dedicated session.
3. In progress. Decide whether to change the production decryption list based on the refresh evidence. If authorized, apply serially under the cluster lease with configuration backups and rollback.
4. Pending. Verify the cluster and the test session after the change, retire the test authorization, and record evidence.

Use only the dedicated test session. Keep token values out of output and documentation.

Production device authorization returned the expected test identity. The original
and renewed refresh tokens both used the dedicated encryption certificate, and
refresh returned HTTP 200. The readiness verifier passed on all three nodes at
revision `48becb9c571aabd4337350d870f54acb00086ede`. The configuration
cutover awaits production authorization.
