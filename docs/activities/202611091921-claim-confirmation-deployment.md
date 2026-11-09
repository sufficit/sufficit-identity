# Claim confirmation preservation deployed

Date: 2026-11-09, America/Sao_Paulo. Maintainer explicitly authorized deployment.

## Release

- Release: 20261109-8cbf3c66.
- Published revision: 8cbf3c662ce7981675b9c8d678577262812c79c3, including correction 408c8cb2.
- Archive SHA-256: 1ee78fcbb55f4ae59590521910e3d0016dca042dd3964ec393bcaa1e3eb5f61f.
- SUI local source: 91f76e061b5561cf8adeafdf311815407061856a, clean.
- Previous release retained on all nodes: 20261109-d04ff980.

Clean-source packaging succeeded with required assets, file permissions and no
bundled production configuration or certificates. Source comparison against the
previous release has no schema/entity/mapping changes; no migration was required
or executed. The package contains the already validated source correction.

## Activation and observations

Preparation verified archive/helper hashes and inherited the four active
configuration files independently on each node. Activation used the cluster
wrapper and coordinator lease, one node at a time. Direct readiness polling saw
transient HTTP 502 responses during restarts, followed by recovery within the
helper deadline; no uninterrupted-service claim is made. No rollback was needed.

All three production nodes (eveo-apps, apoint-apps and castrum-apps) reported the
exact package revision, active service, Healthy liveness and Healthy readiness.
The pinned certificate and JWKS digests stayed unchanged on every node:

- Certificate: 5e858b8d138993436730db83743ac67183495e44de8e2e041e72b2882410eefb.
- JWKS: 85d43862afae2e2eea21c6668aa9ec34fa0c029ac906cd0eaee9122847aed769.

Public HTTPS health, readiness, discovery, confirmation and resend routes returned
HTTP 200. The discovery issuer matched the public origin. The pt-BR confirmation
page requested without account/token parameters rendered the localized invalid
link message and resend action. No personal confirmation token was replayed,
no account was modified and no email was dispatched by these checks.

The source correction passed 72 relevant tests without warnings before packaging.
Production checks establish release identity and availability; they do not claim
an end-to-end confirmation using a real account. Previously invalidated links
still require a fresh resend. Documentation-only follow-up commits do not change
the deployed revision.

See [source correction](202611091910-claim-confirmation-preservation.md) and
[deployment plan](../plans/PLAN-CLAIM-CONFIRMATION-DEPLOY.md).
