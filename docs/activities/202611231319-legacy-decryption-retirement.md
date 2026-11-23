# Legacy token decryption certificates retired

On 23 November 2026 the maintainer authorized removing the two legacy
certificates from the production token-decryption list. The [eligibility
review](202611231252-november-operational-review.md) and the pre-rollout
query found zero unexpired valid or inactive token records issued before
24 October or with an unknown creation date. The public device flow issued
a refresh token for the dedicated test account, and its first renewal
returned HTTP 200. Both refresh tokens identified the dedicated certificate.

The rollout held the cluster deployment lease and updated eveo-apps,
apoint-apps and castrum-apps sequentially. Each node's production
configuration was backed up before atomically changing EncryptionPaths to
contain only certificate-encryption.pfx. Configuration precedence,
the active release, the new process and direct readiness were verified.
The certificate files remain on disk. Configuration backups on each node
are in the root-only directory `/root/identity-legacy-decryption-20261123T1618Z`.
For rollback, restore the previous list and restart sequentially under the
[cluster procedure](../runbooks/RUNBOOK-CLUSTER-ROLLING-DEPLOY.md).

Direct health probes briefly returned 502 during restarts. All three nodes
finished active and ready at revision `48becb9c571aabd4337350d870f54acb00086ede`.
The cluster verifier matched the baseline certificate and JWKS hashes.
Public health, readiness and discovery returned HTTP 200. The refresh
token issued before the change renewed successfully after all three
restarts, and the replacement identified the same dedicated certificate.

The OAuth revocation endpoint returned HTTP 200 for the test access and
refresh credentials. The database confirmed revoked status on all nine
issued access, ID and refresh token records. The ad hoc authorization row
remains present with no active access or refresh credentials from the test.
