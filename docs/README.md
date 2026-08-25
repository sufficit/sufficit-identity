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

Dated evaluations that are useful only as historical evidence live under
`archive/evaluations`.

## Active plans (pending work)

- [GPT-5 evaluation — remaining work](plans/PLAN-GPT-5-REMAINING.md) — residual protocol, trust-boundary and production-assurance work
- [Authorization, SCIM and secret boundaries](plans/PLAN-GLM-5-2-REMAINING.md) — residual authorization, secret and maintainability work
- [Management applications](plans/PLAN-MANAGEMENT-APPLICATIONS.md) — complete OAuth/OIDC application lifecycle in the Management console
- [Production readiness](plans/PLAN-PRODUCTION-READINESS.md) — certification, CSP calibration, WCAG, forward protocols
- [Legacy cutover — operational gates](plans/PLAN-LEGACY-CUTOVER-OPS.md) — clients, keys, rehearsals
- [Pluggable UI — phases 2-5](plans/PLAN-PLUGGABLE-UI-PHASES-2-5.md) — remote UI, BFF, SDK
- [Internal vault](plans/PLAN-VAULT.md) — Phase 1 delivered; named-secret and signing-key phases remain

## Completed work (activities/)

- [Evaluation remediation and god-service decomposition](activities/202608240940-fable-5-evaluation-remediation.md) — vault signature verification, audit retention and volume, administrative rate limiting, refusal-audit rule
- [Identity MCP — Vault and self-service](activities/202608162300-identity-mcp-vault-self-service.md)
- [Reconciliação do plano de autorização, SCIM e segredos](activities/202608092130-security-plan-reconciliation.md)
- [Normalização de nomes e resumos das atividades](activities/202608092120-activity-documentation-normalization.md)
- [Implementação e encerramento do plano de segurança](activities/202608092110-implementation-plan-closure.md)
- [Handoff dos gates operacionais de produção](activities/202608092105-operational-gate-handoff.md)
- [Reconciliação dos refactors arquiteturais P2](activities/202608092100-p2-architecture-reconciliation.md)
- [Formato de access token por cliente e recurso](activities/202608092055-per-client-access-token-format.md)
- [Métrica e orçamento de mensagens AES-GCM](activities/202608092052-vault-encryption-budget-metrics.md)
- [Modelo criptográfico e composição de replay](activities/202608092045-crypto-model-replay-composition.md)
- [Validação integrada P1 — JAR e mTLS](activities/202608092036-p1-integrated-validation.md)
- [Revogação e topologia verificável de mTLS](activities/202608092035-mtls-revocation-topology.md)
- [JAR com `jwks_uri` remoto seguro](activities/202608092022-jar-remote-jwks.md)
- [Vault — autorização de named secrets](activities/202608092010-vault-secret-namespaces.md)
- [Vault — lifecycle distribuído das chaves de assinatura](activities/202608092355-vault-signing-key-lifecycle.md)
- [Vault — isolamento de segredos e consumidores](activities/202608092020-vault-secret-context-and-secret-store.md)
- [Vault — boundaries fail-closed de produção](activities/202608091930-vault-fail-closed-boundaries.md)
- [Sender constraints — exclusividade DPoP/mTLS](activities/202608091925-sender-constraint-exclusivity.md)
- [Invariantes de cliente e Request Object](activities/202608091918-pkce-jar-invariants.md)
- [Políticas sensíveis — defaults seguros](activities/202608091911-secure-policy-defaults.md)
- [Production posture — contributors modulares](activities/202608091904-production-posture-contributors.md)
- [Security hardening wave 2](activities/202608071330-security-hardening-wave-2.md)
- [Correções de segurança de protocolos e fronteiras](activities/202608071227-protocol-security-remediation.md)
- [Endurecimento de segurança, sessão e vault](activities/202608071210-security-hardening.md)
- [Protocol roadmap baseline](activities/202608011800-protocol-roadmap-baseline.md)
- [Legacy cutover — DB/provider gates](activities/202608011820-legacy-cutover-db-provider.md)
- [Pluggable UI — phases 0-1](activities/202608012000-pluggable-ui-phase0-phase1.md)
- [Internal vault — Phase 1](activities/202608081430-vault-phase-1.md)
- [Internal vault — Phases 2/3 foundation](activities/202608081745-vault-phases-2-3-foundation.md)
- [Internal vault — signing provider and JWKS](activities/202608081530-vault-signing-provider-jwks.md)

## Architecture

- [Repository and module architecture](architecture/ARCHITECTURE-REPOSITORY.md)
- [Distributed snapshot cache architecture](architecture/ARCHITECTURE-DISTRIBUTED-CACHE.md)
- [Single-source UI boundary](architecture/ARCHITECTURE-SINGLE-SOURCE-UI.md)
- [Management authorization boundary](architecture/ARCHITECTURE-MANAGEMENT-AUTHORIZATION.md)
- [Public UI architecture](architecture/ARCHITECTURE-PUBLIC-UI.md)

## Design

- [Product definition](design/DESIGN-PRODUCT.md)
- [Visual and interaction system](design/DESIGN-SYSTEM.md)
- [Management product definition](design/DESIGN-MANAGEMENT-PRODUCT.md)
- [Management visual contract](design/DESIGN-MANAGEMENT-UI.md)

## Usage

- [Embedded public and Management UIs](usage/USAGE-EMBEDDED-UI.md)
- [Identity MCP — Vault and self-service](usage/USAGE-IDENTITY-MCP.md)
- [SCIM 2.0](usage/USAGE-SCIM.md)
- [Database migration assets](migration/README.md)

## Operations

- [Deployment configuration](runbooks/RUNBOOK-DEPLOYMENT.md)
- [Distributed cache and snapshot](runbooks/RUNBOOK-DISTRIBUTED-CACHE.md)
- [Production evidence and release gates](runbooks/RUNBOOK-PRODUCTION-EVIDENCE.md)
- [Database connection resilience and monitoring](runbooks/RUNBOOK-DATABASE-CONNECTION-RESILIENCE.md)
- [CSP calibration](runbooks/RUNBOOK-CERTIFICATES — Geração, deploy, rotação e troubleshooting dos certificados de token (assinatura/encriptação/KEK). **CRÍTICO**: o runtime .NET 10.0.10 em produção rejeita PFX gerado por OpenSSL/SDK — ver runbook.
RUNBOOK-CSP-CALIBRATION.md)
- [Confirmed-email rollout](runbooks/RUNBOOK-CONFIRMED-EMAIL.md)
- [Internal vault](runbooks/RUNBOOK-VAULT.md)

## Evaluations

- [Evaluation prompt](evaluations/EVALUATION-PROMPT.md)

An evaluation describes the repository at a point in time. Findings that still
require work must be copied into the relevant active plan; an archived evaluation
must never silently become the current roadmap.
