# Production publication — 20261106-56d0463

Date: 2026-11-06 (America/Sao_Paulo). User explicitly requested deployment.
Parent: [production gates](../plans/PLAN-PRODUCTION-GATES.md).
Build repair: [nullable audit contract](202611061726-deployment-build-repair.md).

## Artifact and validation

Revision: `56d046306578c95be8cfa8b022dd78e3dd7ea2ce`.
Release: `20261106-56d0463`.
Archive: `/tmp/identity-release-20261106-c/20261106-56d0463.tar.gz`.
SHA-256: `4855baadbc109522e629cd5744d84e4edddaa0640ec2caf1a7469f6aaa55b1d4`.
Local SUI revision: `91f76e061b5561cf8adeafdf311815407061856a`.

Built through package-release.sh from a clean detached checkout with local SUI,
following DEPLOY.md. Only generated package-lock edits in that isolated checkout
were reset after restore; parallel locks in the main workspace were preserved.
The archive excludes production configuration/certificates.

Preflight Release warn-as-error build + impersonation/documentation tests:
**18 passed**. Entire Release test project: **2128 passed, 12 skipped**
(TRX total 2140/executed 2128). No schema or mapping change from deployed
206fbb9; no migration was run. GitHub CI/CodeQL for 56d0463 were still running
at publication; they are not claimed successful here.

## Rollout

prepare-cluster-release.sh verified archive/helper hashes and inherited each
node's four top-level configuration files. activate-cluster-release.sh held
the shared deployment lease and activated sequentially:

- eveo-apps.sufficit.com.br
- castrum-apps.sufficit.com.br
- apoint-apps.sufficit.com.br

All three report the exact revision, active/running service, NRestarts=0 and Healthy liveness/readiness.
The post-activation uniformity gate passed with unchanged explicit pins:

- Certificate SHA-256: `5e858b8d138993436730db83743ac67183495e44de8e2e041e72b2882410eefb`.
- JWKS SHA-256: `85d43862afae2e2eea21c6668aa9ec34fa0c029ac906cd0eaee9122847aed769`.

Public HTTPS probes returned 200 for /health, /health/ready, discovery and
/account/login. Discovery issuer is `https://identity.sufficit.com.br/`;
login returns an enforcing Content-Security-Policy header.

The activation probes saw transient 502 responses during restarts, then recovered.
Zero downtime is not claimed. No authenticated end-user transaction was performed.
Previous release `20261106-206fbb9` remains available on all nodes for rollback.
No live secrets, users, grants, certificates or configuration were intentionally changed.

## Delivery

Deployment is complete. MarkdownCoverageTests: **8 passed**; `git diff --check`: clean. The operational gates elsewhere remain open.
