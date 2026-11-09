# Email confirmation recovery deployment

Date: 2026-11-09, America/Sao_Paulo. Maintainer explicitly authorized deployment.

## Published release

- Release: `20261109-d04ff980`.
- Identity revision: `d04ff98072e7ead121cb49dd7fb6859ea4cc175e`, including
  the recovery correction in `e365dd93`.
- SUI source revision: `91f76e061b5561cf8adeafdf311815407061856a`, clean.
- Archive SHA-256: `1068f3759bc5e43f59c738d69fa714cbd7f696577fa205f618612725f14eacd4`.
- Previous release on every node: `20261106-e1aeb174`, revision
  `e1aeb17488af8b82af3fd270853a51c88cb94b15`; retained as rollback baseline.

## Preparation and activation

The package helper built the clean revision and verified required binaries,
static assets, permissions and absence of runtime configuration/certificates.
No core migration, mapping or entity changes exist against the previous release;
no database migration was required or run.

Cluster preparation verified archive/helper hashes and inherited all four
configuration files locally on each node. The cluster activation wrapper acquired
its coordinator lease, verified candidate identity/configuration, and activated
one node at a time. No direct manual service restart was used.

Readiness polling at individual nodes returned transient HTTP 502 during service
restarts and recovered within the helper deadline. No uninterrupted-request
claim is made. No rollback was required.

## Observed production evidence

All three nodes (eveo-apps, apoint-apps and castrum-apps) reported the exact
published revision, active service, Healthy liveness and Healthy readiness.
Certificate/JWKS digests were uniform and unchanged from the preflight:

- Certificate SHA-256: `5e858b8d138993436730db83743ac67183495e44de8e2e041e72b2882410eefb`.
- JWKS SHA-256: `85d43862afae2e2eea21c6668aa9ec34fa0c029ac906cd0eaee9122847aed769`.

Public HTTPS returned HTTP 200 for `/health`, `/health/ready`, discovery,
`/account/confirmemail` and `/account/resendemailconfirmation`. Discovery issuer
matched the public origin. The confirmation page, requested without account/token
parameters and with pt-BR Accept-Language, rendered the localized invalid/expired
message and resend action. The raw `Invalid token.` text was absent.

No real confirmation token was replayed, no account was changed, and no email
was dispatched by these checks. The original token's exact rejection reason
remains unknown; deployment publishes the recovery behavior, not a bypass of
validation. See the [correction evidence](202611091328-email-confirmation-recovery.md).

Eight Markdown coverage tests passed with no warnings. The source correction
already passed 43 focused tests. The [deployment plan](../plans/PLAN-EMAIL-CONFIRMATION-DEPLOY.md)
records completed checkpoints. Follow-up documentation commits do not change the
published application revision.
