# Documentation index

This directory is organized by document purpose. `README.md` is reserved for
indexes; every other Markdown file uses `TYPE-SUBJECT.md`, with an uppercase
type prefix and an uppercase kebab-case subject. Completed work is archived in
`activities/` with a `YYYYMMDDHHmm-` timestamp prefix.

## Naming convention

| Prefix | Use |
| --- | --- |
| `ARCHITECTURE-` | Durable boundaries, ownership and technical decisions |
| `DESIGN-` | Product intent, interaction and visual-system rules |
| `PLAN-` | Active work with explicit gates — only pending items |
| `RUNBOOK-` | Ordered operational procedure, validation and rollback |
| `USAGE-` | Configuration and consumer-facing use of an implemented feature |
| `EVALUATION-` | Evaluation instructions or dated assessment |
| `INVESTIGATION-` | Time-bounded evidence, diagnosis and conclusions |
| `RFC-` | Conformance with an IETF RFC, under `rfc/` |
| `SPEC-` | Conformance with a non-IETF specification (OpenID Foundation, W3C, drafts), under `rfc/` |

Dated evaluations that are useful only as historical evidence live under
`archive/evaluations`.

## Specification conformance

[`rfc/README.md`](rfc/README.md) indexes one document per implemented RFC or
specification, with coverage level, implementation origin (OpenIddict,
in-house or mixed) and known gaps. The source of truth is the code: each
claim cites `file:line`.

## The plan (pending work)

There is one plan: [`plans/PLAN-IDENTITY.md`](plans/PLAN-IDENTITY.md). It consolidates the twelve
that preceded it, each reconciled against the working tree first, and organises
what is left by the boundary it belongs to rather than by which evaluation
found it.

| Section | What it owns |
|---|---|
| A | Authorization and trust boundaries — context ownership, SCIM, step-up, passkey assurance |
| B | Token issuance and claim release — the issuance kernel, claims, token exchange, DPoP, CIBA, JAR/JARM |
| C | Secrets, keys and transport — plaintext gate, vault rotation, key separation, verified TLS |
| D | Production posture — posture-check coverage, CSP enforcement, topology, abuse protection |
| E | Administration console and UI — client operational state, application lifecycle, result states, pluggable UI |
| F | Platform and architectural debt — god-files, SCIM decomposition, provider fork, MariaDB baseline |
| G | Observability, conformance and cutover — certification, external audit, legacy cutover gates |

## Completed work (activities/)

- [Six settings the production posture check was not looking at](activities/202609191900-posture-check-coverage.md) — legacy grants block startup; permissive CSP sources, one certificate for two purposes, token exchange on by default, optional passkey verification and unmapped claims are reported
- [A passkey now claims only what the ceremony proved](activities/202609191700-passkey-assurance.md) — `amr=mfa` derived from the WebAuthn user-verification flag instead of asserted before the ceremony
- [Account enumeration, legacy grants and a default interface method](activities/202609191500-enumeration-legacy-grants-revoker.md) — sign-in no longer reveals a locked or unconfirmed account to a wrong password; `implicit` refused outright and `password` gated on the deployment; the session revoker's dropped argument
- [Evaluation remediation and god-service decomposition](activities/202608240940-fable-5-evaluation-remediation.md) — vault signature verification, audit retention and volume, administrative rate limiting, refusal-audit rule
- [Identity MCP — Vault and self-service](activities/202608162300-identity-mcp-vault-self-service.md)
- [Authorization, SCIM and secrets plan reconciliation](activities/202608092130-security-plan-reconciliation.md)
- [Activity name and summary normalization](activities/202608092120-activity-documentation-normalization.md)
- [Security plan implementation and closure](activities/202608092110-implementation-plan-closure.md)
- [Production operational gate handoff](activities/202608092105-operational-gate-handoff.md)
- [P2 architectural refactor reconciliation](activities/202608092100-p2-architecture-reconciliation.md)
- [Per-client and per-resource access token format](activities/202608092055-per-client-access-token-format.md)
- [AES-GCM message metrics and budget](activities/202608092052-vault-encryption-budget-metrics.md)
- [Cryptographic model and replay composition](activities/202608092045-crypto-model-replay-composition.md)
- [P1 integrated validation — JAR and mTLS](activities/202608092036-p1-integrated-validation.md)
- [mTLS revocation and verifiable topology](activities/202608092035-mtls-revocation-topology.md)
- [JAR with secure remote `jwks_uri`](activities/202608092022-jar-remote-jwks.md)
- [Vault — named secret authorization](activities/202608092010-vault-secret-namespaces.md)
- [Vault — distributed signing key lifecycle](activities/202608092355-vault-signing-key-lifecycle.md)
- [Vault — secret and consumer isolation](activities/202608092020-vault-secret-context-and-secret-store.md)
- [Vault — production fail-closed boundaries](activities/202608091930-vault-fail-closed-boundaries.md)
- [Sender constraints — DPoP/mTLS exclusivity](activities/202608091925-sender-constraint-exclusivity.md)
- [Client and Request Object invariants](activities/202608091918-pkce-jar-invariants.md)
- [Sensitive policies — secure defaults](activities/202608091911-secure-policy-defaults.md)
- [Production posture — modular contributors](activities/202608091904-production-posture-contributors.md)
- [Security hardening wave 2](activities/202608071330-security-hardening-wave-2.md)
- [Protocol and boundary security fixes](activities/202608071227-protocol-security-remediation.md)
- [Security, session and vault hardening](activities/202608071210-security-hardening.md)
- [Protocol roadmap baseline](activities/202608011800-protocol-roadmap-baseline.md)
- [Legacy cutover — DB/provider gates](activities/202608011820-legacy-cutover-db-provider.md)
- [Pluggable UI — phases 0-1](activities/202608012000-pluggable-ui-phase0-phase1.md)
- [Internal vault — Phase 1](activities/202608081430-vault-phase-1.md)
- [Internal vault — Phases 2/3 foundation](activities/202608081745-vault-phases-2-3-foundation.md)
- [Internal vault — signing provider and JWKS](activities/202608081530-vault-signing-provider-jwks.md)

## Architecture

- [Repository and module architecture](architecture/ARCHITECTURE-REPOSITORY.md)
- [Revogação de tokens e limpeza de registros](architecture/ARCHITECTURE-TOKEN-REVOCATION.md)
- [Distributed snapshot cache architecture](architecture/ARCHITECTURE-DISTRIBUTED-CACHE.md)
- [Single-source UI boundary](architecture/ARCHITECTURE-SINGLE-SOURCE-UI.md)
- [Management authorization boundary](architecture/ARCHITECTURE-MANAGEMENT-AUTHORIZATION.md)
- [Public UI architecture](architecture/ARCHITECTURE-PUBLIC-UI.md)

## Design

- [Product definition](design/DESIGN-PRODUCT.md)
- [Visual and interaction system](design/DESIGN-SYSTEM.md)
- [Management product definition](design/DESIGN-MANAGEMENT-PRODUCT.md)
- [Management visual contract](design/DESIGN-MANAGEMENT-UI.md)
- [Audience management surface](design/DESIGN-AUDIENCES.md)

## Usage

- [Audience management](management/USAGE-AUDIENCES.md) — inventory, scope bindings, permissions and audit.

- [Opening and closing the Device Flow in a popup](design/DESIGN-DEVICE-FLOW-POPUP.md) — launcher for Symposium, messaging and browser limits.

- [Browser, API and Playwright classification](networking/USAGE-BROWSER-API-CLASSIFICATION.md) — HTML/JSON presentation rules, limits and reuse.

- [Rate limiting by operation and browser errors](networking/USAGE-RATE-LIMITING.md)

- [Managed client credentials](usage/USAGE-MANAGED-CLIENT-CREDENTIALS.md) — validade, rotação e emissão de tokens de aplicação

- [Embedded public and Management UIs](usage/USAGE-EMBEDDED-UI.md)
- [Identity MCP — Vault and self-service](usage/USAGE-IDENTITY-MCP.md)
- [SCIM 2.0](usage/USAGE-SCIM.md)
- [Database migration assets](migration/README.md)

## Operations

- [Deployment configuration](runbooks/RUNBOOK-DEPLOYMENT.md)
- [Distributed cache and snapshot](runbooks/RUNBOOK-DISTRIBUTED-CACHE.md)
- [Production evidence and release gates](runbooks/RUNBOOK-PRODUCTION-EVIDENCE.md)
- [Database connection resilience and monitoring](runbooks/RUNBOOK-DATABASE-CONNECTION-RESILIENCE.md)
- [Token certificates (signing & encryption)](runbooks/RUNBOOK-CERTIFICATES.md) — generation, deployment, rotation and troubleshooting of token certificates (signing/encryption/KEK). **CRITICAL**: the .NET 10.0.10 runtime in production rejects PFX files generated by OpenSSL/SDK — see runbook.
- [CSP calibration](runbooks/RUNBOOK-CSP-CALIBRATION.md)
- [Confirmed-email rollout](runbooks/RUNBOOK-CONFIRMED-EMAIL.md)
- [Internal vault](runbooks/RUNBOOK-VAULT.md)

## Evaluations

- [Evaluation prompt](evaluations/EVALUATION-PROMPT.md)

An evaluation describes the repository at a point in time. Findings that still
require work must be copied into the relevant active plan; an archived evaluation
must never silently become the current roadmap.

## Shared patterns

- [Runtime snapshots](architecture/ARCHITECTURE-RUNTIME-SNAPSHOTS.md) — reference to the Sufficit contract and differences from the current implementation.

- [Limpeza centralizada de tokens e alerta de atraso](operations/RUNBOOK-TOKEN-PRUNING.md)
