# GPT-5 evaluation — remaining work

> **Status:** ACTIVE. This plan contains only work that remained partial or
> unimplemented when the 2026-08-07 GPT-5 evaluation was reconciled against
> `79e0f82`. Delivered work is recorded in
> `docs/activities/202608071227-protocol-security-remediation.md` and the later
> `docs/activities/202608071330-security-hardening-wave-2.md`.

The compound checklists below remain as release acceptance criteria. The
second activity records the code-level controls now present; unchecked
operational inventory, enforcement, conformance, multi-replica and lifecycle
requirements remain mandatory and prevent this plan from being closed.

## Delivery constraint

The STS serves production traffic. Preserve existing grants, clients, users and
integrations through additive schema, compatibility adapters, audit/shadow
decisions and rolling deployment. Enforcement may replace compatibility only
after telemetry demonstrates that current production traffic satisfies the new
policy. A feature that cannot meet its security invariant must remain disabled
instead of advertising partial assurance.

## P0 — close exposed security boundaries

### 1. Unify token issuance and make release policies deny-by-default (V-03, V-08, V-10)

- [ ] Introduce `ITokenIssuanceService` and an issuance request/result contract shared by OpenIddict grants, PAT and CIBA
- [ ] Centralize subject rehydration, claim destinations, scope/resource/audience attenuation, lifetime, token format, sender constraint, persistence, revocation, audit and metrics
- [ ] Add `IPersonalTokenIssuancePolicy`: require a dedicated management scope, recent strong authentication, fixed audiences, explicit requested scopes intersected with caller and current application grants, and a deployment-bounded lifetime
- [ ] Add `IClaimReleasePolicy` that considers client, grant, scopes, resources and destination; inventory current claims in shadow mode, migrate consumers and set `IncludeUnmappedClaimsInAccessTokens=false`
- [ ] Retain the existing token-exchange resource rejection and add a closed actor/presenter allow-list, `may_act` semantics, delegation-depth bounds and actor-chain audit
- [ ] Characterize every current token shape and migrate one grant at a time without changing public routes

**Done when:** PAT and CIBA no longer use a parallel issuance path, no unmapped
application claim is released, and every scope/resource/lifetime decision is
produced by one tested policy kernel.

### 2. Isolate DPoP nonce state (V-06)

- [ ] Replace the singleton nonce key with state partitioned by authenticated client, proof key or bounded transaction
- [ ] Rotate only after client authentication and structurally plausible proof validation; retain a small bounded grace set for legitimate retries
- [ ] Implement atomic issue/consume semantics in the shared security-state store and add concurrent multi-replica tests
- [ ] Add anonymous-rotation and cross-client denial-of-service regression tests

**Done when:** one anonymous or compromised client cannot invalidate another
client's proof and concurrent replicas agree on accepted nonce state.

### 3. Complete the CIBA trust boundary (V-08)

- [ ] Require explicit CIBA endpoint/grant permission and a confidential client authenticated by an approved strong method
- [ ] Display and bind `binding_message` in the approval ceremony, with expiry, user intent and anti-phishing tests
- [ ] Move token creation to the unified issuance kernel and the standard token-processing boundary while retaining atomic one-shot consumption
- [ ] Map CIBA services, routes and metadata as one feature unit so disabled means 404 and no advertisement
- [ ] Run CIBA interoperability/conformance and approval-fatigue abuse tests before enabling additional clients

**Done when:** only provisioned strong clients can initiate CIBA, the user sees
the transaction binding, and issued artifacts obey the same policies as other
grants.

### 4. Make mTLS/FAPI assurance real before advertising it (V-09)

- [ ] Add deployment attestation for direct TLS or a specifically trusted certificate-forwarding proxy; fail startup when mTLS is enabled without it
- [ ] Enroll and bind client certificates to application metadata and derive authentication assurance from the method actually validated
- [ ] Emit and enforce certificate-bound access-token confirmation (`cnf`) through supported OpenIddict/resource-server primitives
- [ ] Separate workforce/client-certificate trust and define rotation/overlap/revocation procedures per application
- [ ] Stop advertising FAPI/mTLS metadata until the deployment passes the official FAPI 2.0 conformance profile

**Done when:** arbitrary accepted certificates cannot satisfy a client profile,
tokens are cryptographically sender-constrained, and metadata matches proven
runtime behavior.

### 5. Enforce step-up and project authentication context (V-12, V-20)

- [ ] Add an explicit reauthentication ceremony for passkey, password, recovery-code, MFA and external-login mutations
- [ ] Persist transaction-bound `auth_time`, `amr`, `acr`/AAL in the authenticated session when factors complete
- [ ] Project that session evidence into authorization codes and access tokens through `IAuthenticationContextProjector`, never through durable user claims
- [ ] Change credential-mutation step-up from Audit to Enforce after current sessions and UI flows pass canary checks
- [ ] Add end-to-end tests proving a real MFA login can satisfy Management/SCIM policies and stale sessions cannot mutate credentials

**Done when:** sensitive account persistence requires recent strong evidence and
tokens carry verifiable evidence from the actual authentication ceremony.

### 6. Finish origin, secret, key and transport enforcement (V-13–V-16)

- [ ] Inventory proxy paths and public hosts, eliminate request-derived security URLs and switch `PublicOrigin.Mode` to `Enforce`
- [ ] Complete credential rotation, plaintext migration and Vault production enforcement through `PLAN-GLM-5-2-REMAINING.md` P0.1 and `PLAN-VAULT.md`
- [ ] Introduce purpose-separated protocol signing/encryption keys with active/retiring overlap, stable `kid`, JWKS rotation and a KMS/HSM-backed production provider
- [ ] Separate token, Data Protection and TLS key material; validate compromise and rollback procedures
- [ ] Make releases root-owned/read-only, restrict writable state directories and harden the systemd unit with least-privilege sandboxing
- [ ] Migrate RabbitMQ and SMTP to verified TLS, then enable each `RequireTls` production gate

**Done when:** no security link derives authority from the request, no production
secret or reset token has a plaintext path, keys rotate without invalidating
valid overlap traffic, and the service process cannot modify its release.

### 7. Enforce tenant-aware Management authorization (V-19)

- [ ] Implement the ownership/context model and non-permissive object policy in `PLAN-GLM-5-2-REMAINING.md` P0.3
- [ ] Separate operator entitlements from roles/scopes issued to managed identities
- [ ] Filter collection queries as well as item mutations and test enumeration, guessed identifiers and cross-context operations
- [ ] Keep an audited, narrowly assigned break-glass administrator path

**Done when:** the configured context changes authorization outcomes and no
administrator gains global object access merely by holding a generic role.

## P1 — protocol lifecycle and architecture

### 8. Complete JAR/JARM validation and key ownership (V-17, V-18)

- [ ] Require JAR `typ`, `iat`, `exp` and `jti`, enforce freshness/max lifetime and atomically reject replay per client
- [ ] Preserve structured/multi-valued request-object parameters and cover canonicalization edge cases
- [ ] Resolve JARM encryption keys and allowed algorithms from each client's public metadata; never encrypt all client responses with a server-global private key
- [ ] Add rotation, negative interoperability and feature-off tests before enabling either profile

### 9. Replace local IP limiting with distributed abuse protection (V-22)

- [ ] Implement shared partitions by endpoint, client, HMAC-normalized account and IP with progressive delay and bounded lockout behavior
- [ ] Add dummy password work and response/timing normalization where user existence can be inferred
- [ ] Validate trusted-proxy configuration at startup and integrate edge/WAF signals without treating them as the only control
- [ ] Tune using production shadow metrics, including NAT false-positive and botnet-spray scenarios

### 10. Complete dynamic client registration lifecycle (V-24)

- [ ] Use short-lived/single-use registration access credentials and generate client identifiers/secrets server-side
- [ ] Apply one canonical metadata validator, including strict URI schemes and loopback redirect rules
- [ ] Implement protected read, update, delete, secret rotation and audit lifecycle
- [ ] Align operator-managed application lifecycle and secret references with `PLAN-MANAGEMENT-APPLICATIONS.md`
- [ ] Keep DCR disabled until lifecycle, abuse controls and interoperability tests are complete

### 11. Decouple server-side sessions from per-request database writes (V-25)

- [ ] Introduce a cancellation-aware session repository with shared cache, bounded write-behind activity updates and explicit revocation invalidation
- [ ] Define database/cache outage behavior so temporary storage failure does not create an unbounded login outage or accept revoked sessions indefinitely
- [ ] Add multi-replica consistency, stale-cache, failover and cancellation tests

### 12. Move schema migration out of the web process (V-26)

- [ ] Create a dedicated migrator/job that obtains a database advisory lock and reports migration health separately
- [ ] Keep `AutoMigrate=false` in production and remove web-process migration responsibility after deployment automation adopts the migrator
- [ ] Test two-replica startup, failed migration, retry and old-binary rollback against additive schema

### 13. Complete architectural boundaries from the evaluation

- [ ] Make protocol modules register services, OpenIddict handlers, validation, routes and metadata as one feature-on/off unit
- [ ] Move interfaces/DTOs physically into Application Abstractions and remove external `Compile Include` plus dual-purpose preprocessor compilation
- [ ] Decompose SCIM parsing, user/group provisioning, PATCH, persistence and publishing through `PLAN-GLM-5-2-REMAINING.md` P1.6
- [ ] Split operational/security contexts and migrations only after transactional boundaries and outbox behavior are defined

## P2 — production proof

### 14. Verify distributed, browser and protocol behavior

- [ ] Configure the real shared cache/state backend and prove DPoP, CIBA, passkey and session behavior across replicas
- [ ] Run OAuth/OIDC/FAPI/SSF conformance suites appropriate to every advertised capability
- [ ] Add browser tests for passkey registration/login, 2FA, consent, CSP and step-up on supported desktop/mobile engines
- [ ] Add real MariaDB/Redis concurrency tests, feature-off 404 tests, host-poisoning tests and key/cache/database fault injection
- [ ] Verify egress firewall and every approved outbound target in the production topology
- [ ] Commission independent review of custom protocol/security code and track certification through `PLAN-PRODUCTION-READINESS.md`

### 15. Make security decisions observable

- [ ] Emit structured, PII-safe events for issuance policy, actor chain, PAT, step-up, replay, egress denial, key rotation and authorization denial
- [ ] Deliver security audit through a durable outbox and define retention, integrity and access-control policy
- [ ] Add alerts for compatibility fallback, plaintext/TLS warnings, replay pressure, unexpected public origin and expiring keys

## Residual finding map

| Finding | Remaining owner |
| --- | --- |
| V-03, V-10 | P0.1 |
| V-04 | P0.1 unified-policy follow-through; reported resource amplification is closed |
| V-06 | P0.2 |
| V-08 | P0.1 and P0.3 |
| V-09 | P0.4 |
| V-12, V-20 | P0.5 |
| V-13–V-16 | P0.6 plus `PLAN-GLM-5-2-REMAINING.md` / `PLAN-VAULT.md` |
| V-17, V-18 | P1.8 |
| V-19 | P0.7 |
| V-22 | P1.9 |
| V-24 | P1.10 plus `PLAN-MANAGEMENT-APPLICATIONS.md` |
| V-25 | P1.11 |
| V-26 | P1.12 |
| Architecture and assurance backlog | P1.13, P2.14–P2.15 |
