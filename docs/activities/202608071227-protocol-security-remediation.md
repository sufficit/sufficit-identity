# Correções de segurança de protocolos e fronteiras — trabalho concluído

**Data:** 2026-08-07
**Versão validada:** `79e0f82` (implementação equivalente em runtime a `f97ef7e`)

## Outcome

The security review was reconciled with the implementation delivered after its
cutoff. Eight findings have their reported exploit boundary closed in code,
while another nine received deployable foundations that intentionally remain
in compatibility or audit mode. Every residual requirement is retained in
the corresponding implementation plan or in a referenced canonical plan.

This activity records implemented behavior only. It does not treat an audit
mode, an extension point, or an operational runbook as enforcement evidence.

## Closed findings

| Finding | Implemented result | Principal evidence |
| --- | --- | --- |
| V-01 — SSF client isolation | Streams persist their owner and every list, read, mutation, verification and poll operation is scoped to the authenticated presenter. | `SsfStream`, `SsfStreamStore`, `SsfStreamsController`, `SsfPollController`, migration `HardenSsfStreams` |
| V-02 — SSF filters and verification | Event/subject matching is enforced, verification challenges are hashed and expiring, pending streams cannot receive ordinary events, and delivery keys are unique. | `ISsfSubscriptionMatcher`, `SharedSignalsDispatcher`, `SsfStreamStore`, SSF tests |
| V-04 — token-exchange resource amplification | Requested scopes are attenuated and a resource outside the subject token delegation is rejected. | `AuthorizationController`, token-exchange resource tests |
| V-05 — DPoP downgrade and replay | DPoP validation runs at resource-server validation boundaries, a present invalid proof fails, and replay is guarded by database-authoritative atomic state. | `DpopValidationHandlers`, `RollingDpopReplayCache`, `DatabaseDpopReplayCache`, DPoP tests |
| V-07 — unused/broken SSRF defense | Outbound clients use a common IP-pinned policy with scheme/host controls, private-address policy and redirects disabled. | `SafeHttpHandlerFactory`; metrics, CAPTCHA, HIBP, logout and SSF registrations |
| V-11 — credential mutation without revocation | Password, MFA, passkey and external-login mutations update the security state and revoke OAuth artifacts and other browser sessions through one coordinator. | `CredentialMutationSecurityCoordinator` and credential-flow integrations |
| V-21 — WebAuthn blocked by security header | The same-origin WebAuthn capabilities required by the public UI are allowed by `Permissions-Policy`. | `SecurityHeadersMiddlewareExtensions`, security-header tests |
| V-23 — missing SCIM denial audit | Authorization failures are recorded at the middleware result boundary, including 401/403 responses that never enter an action filter. | SCIM `IAuthorizationMiddlewareResultHandler`, denial-audit tests |

SSF durable push retry remains a production-readiness enhancement; it does not
reopen the ownership, filtering or verification defects above.

## Completed foundations with residual enforcement work

| Finding | Foundation delivered | Why it remains open |
| --- | --- | --- |
| V-03 — PAT amplification | PATs accept an explicit scope subset and reject scopes outside the configured issuance allow-list; omission retains the historical scope set for compatibility. | Intersection with caller/current application grants, a dedicated management scope, recent authentication, stricter lifetime policy and the unified issuance kernel remain pending. |
| V-08 — CIBA state and issuance | Pending state and one-shot consumption are database-authoritative and atomic; issued tokens are tracked for introspection/revocation with coherent scope/resource/lifetime metadata. | Client eligibility, binding-message UX, standard issuance integration and conformance remain pending. |
| V-10 — claim release | A shared application claim-destination policy and scope map exist. | Compatibility currently permits unmapped claims until inventory and consumer migration allow deny-by-default enforcement. |
| V-12 — credential step-up | A common recent-authentication/step-up coordinator is wired into credential mutations. | Production remains in audit-compatible rollout until reauthentication UX and enforcement are proven. |
| V-13 — request-derived security origins | Reset/confirmation links and metadata can use a canonical configured public origin with Audit/Enforce rollout. | Production must prove proxy/origin inventory and switch to Enforce. |
| V-14 — fail-open secret storage | Vault envelope encryption, versioned ciphertext and migration compatibility are implemented. | Runtime plaintext inventory, rotation and `RequireEncryptionInProduction` enforcement remain operational work. |
| V-15 — key/release lifecycle | Production rejects self-signed fallback, validates persistent signing material, preserves releases and supports atomic activation/rollback. | Purpose-separated active/retiring keys, KMS/HSM and systemd/filesystem hardening remain pending. |
| V-16 — plaintext reset-token transports | SMTP and RabbitMQ have TLS configuration, validation and production warning/enforcement switches. | Production transport endpoints must be migrated and the `RequireTls` switches enforced. |
| V-19 — broken Management routing/auth switch | The configured route prefix is applied consistently and the authorization policy is always registered. | The default object policy is still permissive and needs tenant/context enforcement. |

## Additional architecture delivered

- Additive migrations introduced SSF ownership plus atomic DPoP/CIBA state and
  remain compatible with rolling deployment and application rollback.
- Public-origin, certificate-expiry, Vault, claim-release, transport-TLS and
  step-up controls support observation before enforcement.
- SCIM resource locations now use the canonical origin boundary.
- Release activation is atomic and retains the previous release for rollback.

## Delivery evidence

- `30a793d` — protocol state, SSF ownership/filtering and atomic release activation
- `89b3a56`, `5638783` — coordinated credential mutation and CIBA token/state hardening
- `37a6a0b` — canonical origin, certificate and Vault rollout controls
- `fac0cc0`, `38f7627` — outbound transport/routing hardening and SCIM audit/location fixes
- `b9e7c5f` — encrypted Vault migration compatibility
- `f97ef7e` — validated deployable runtime baseline

The compatibility rollout, additive migrations and canary checks are preserved
in the archived deployment record as historical deployment evidence.

## Reconciliation map

| Evaluation item | State after reconciliation | Destination for residual work |
| --- | --- | --- |
| V-01, V-02 | closed | SSF durable delivery only in `PLAN-PRODUCTION-READINESS.md` |
| V-03 | partial | P0.1 do plano de autorização |
| V-04 | reported amplification closed | unified issuance in P0.1 |
| V-05 | closed | multi-replica proof in P2.14 |
| V-06 | open | P0.2 |
| V-07 | closed | egress deployment validation in P2.14 |
| V-08 | partial | P0.3 |
| V-09 | open | P0.4 |
| V-10 | partial | P0.1 |
| V-11 | closed | — |
| V-12, V-13 | partial | P0.5–P0.6 |
| V-14, V-15, V-16 | partial | P0.6 e planos canônicos do vault |
| V-17, V-18 | open | P1.8 |
| V-19 | routing fixed, tenant policy open | P0.7 e autorização de objetos |
| V-20 | open | P0.5 |
| V-21, V-23 | closed | browser/operational proof in P2.14 |
| V-22 | open | P1.9 |
| V-24 | open | P1.10 and `PLAN-MANAGEMENT-APPLICATIONS.md` |
| V-25 | open | P1.11 |
| V-26 | operationally mitigated, architecture open | P1.12 |
