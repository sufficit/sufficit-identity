# Activity — Publication preflight and prepared artifact

Date: 2026-11-06. User authorized production publication.

## Outcome

Publication **not activated**. Read-only SSH checks on all three production apps
nodes found active services with `/opt/sufficit-identity` as an ordinary directory,
not a release symlink, and no release REVISION marker on the inspected primary.
The current prepare and activate cluster wrappers explicitly reject active paths
outside `/opt/sufficit-identity.releases`. No service was restarted, no production
file was changed and no credential was read into the workstation output.

The process environment on each node has CSP ReportOnly=false,
AcknowledgeReportOnly=false and AllowLegacyBooleanAcknowledgements=false. The
new CSP acknowledgement requirement is therefore not the publication blocker.

## Artifact

- Identity revision: `8ccf3cf959a4d135e128996d6e844f491b9b8795` (application code
  through `7d2ddf0`, plus publication checkpoint documentation).
- Local SUI revision: `91f76e061b5561cf8adeafdf311815407061856a`, clean checkout.
- Archive: `/tmp/identity-release-20261106/20261106-8ccf3cf.tar.gz` on the build host.
- SHA-256: `bd10df8839f0dbb07b1146d5d3b0e1bfed9dbe28405efc15214a786b50f70973`.
- Local SUI restore and `helpers/package-release.sh` succeeded; packaging output
  has no compiler warning/error lines. The wrapper verified required binaries,
  static assets, permissions and absence of runtime configuration/certificates.
- Package-mode lockfiles changed by local SUI restore were restored to their
  original committed contents; no dependency changes were committed.
- CI for application revision `7d2ddf0` was still running at inspection; no
  successful full-CI result or production migration is claimed here.

## Required continuation

Migrate the legacy directory layout into versioned releases with a verified
rollback baseline under the deployment locks, reconcile the deployed schema with
the candidate, then prepare and activate using the
[cluster runbook](../runbooks/RUNBOOK-CLUSTER-ROLLING-DEPLOY.md). Do not bypass the
wrapper's layout guard or count this artifact as a production publication.

The [production plan](../plans/PLAN-PRODUCTION-GATES.md) retains the blocked
preparation and pending activation checkpoints.
