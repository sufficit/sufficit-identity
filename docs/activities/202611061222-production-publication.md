# Activity — Production publication completed

Date: 2026-11-06, America/Sao_Paulo. Publication and continuation authorized by
user. This completes the publication previously blocked by the
[legacy directory layout](202611061218-publication-preflight.md).

## Release

- Release: `20261106-8ccf3cf`.
- Identity revision: `8ccf3cf959a4d135e128996d6e844f491b9b8795`, containing
  application changes through `7d2ddf0` and publication checkpoint documentation.
- SUI source: `91f76e061b5561cf8adeafdf311815407061856a`.
- Archive SHA-256: `bd10df8839f0dbb07b1146d5d3b0e1bfed9dbe28405efc15214a786b50f70973`.
- Prior binary informational revision on all nodes:
  `aa6fefc3913276315d1e2634c245d426ba1295b2`.
- CI run `42241165568` for application revision `7d2ddf0`: completed successfully.

## Legacy layout migration

The original directory was retained as
`/opt/sufficit-identity.releases/legacy-20261106-before-8ccf3cf` on each node.
Under the local/remote cluster lease and each host's deployment lock, a temporary
self-pointing symlink at that baseline path was atomically exchanged with the
active directory using Linux `renameat2(RENAME_EXCHANGE)`. This leaves the active
path pointing at the original directory now stored as the baseline, without a
missing-path interval or copying configuration. Filesystem device and exchange
support were checked first using disposable paths. Each exchange verified an
unchanged service PID and successful readiness; failure would exchange back.
No service was restarted during this layout migration.

All installed bootstrap/prestart/activation helper hashes matched the current
versioned helpers. The prepared archive was verified and each node's complete
configuration set was inherited by the preparation wrapper. Certificate overlap
material was retained by the bootstrap helper.

## Schema and activation

Comparing the actual previous revision with the candidate found no changes to
EF migrations or data configuration. The only entity change was XML comments on
the audit record. No database migration was needed or executed for this release.

`helpers/prepare-cluster-release.sh` prepared the same archive on all three nodes.
`helpers/activate-cluster-release.sh` activated one node at a time with its
rollback protection, then passed its uniformity gate. Direct-node readiness
polling briefly saw HTTP 502 during restarts and recovered within the wrapper's
deadline. No claim of uninterrupted public requests is made from those probes.

## Observed production validation

All three nodes reported:

- exact release REVISION `8ccf3cf959a4d135e128996d6e844f491b9b8795`;
- service active, liveness Healthy, readiness Healthy;
- certificate SHA-256 `5e858b8d138993436730db83743ac67183495e44de8e2e041e72b2882410eefb`;
- JWKS SHA-256 `85d43862afae2e2eea21c6668aa9ec34fa0c029ac906cd0eaee9122847aed769`.

Public HTTPS returned 200 for `/health`, `/health/ready`, OIDC discovery and
`/account/login`. Discovery issuer matched the public origin and the login
response carried enforcing Content-Security-Policy. These probes do not exercise
an authenticated end-user flow. No user/client credentials or policy settings
were changed. Production A2 telemetry/migration gates remain separate work.

Rollback baseline remains available through the documented
[cluster activation procedure](../runbooks/RUNBOOK-CLUSTER-ROLLING-DEPLOY.md).
The baseline name can be used as the expected legacy revision (it has no REVISION
file); never rewrite its marker to pretend that it is the new source revision.

All publication checkpoints are complete. Subsequent documentation commits do
not change the published application revision.
