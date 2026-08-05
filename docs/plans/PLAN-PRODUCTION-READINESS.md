# Production readiness — remaining work

> **Status:** All evaluation security findings are closed (16/17). Protocol coverage is complete. The items below are the gap between "code-complete" and "production-ready for regulated/high-assurance workloads."

## Certification
- [ ] Run OpenID Foundation FAPI 2.0 conformance suite and submit for formal certification
- [ ] Commission an external security audit (independent review of hand-rolled DPoP, CIBA, JARM, JAR, SSF code)

## Operational hardening
- [ ] Execute RUNBOOK-CONFIRMED-EMAIL (confirmed-email rollout + legacy user migration query)
- [ ] Calibrate CSP against the real Blazor UI (exercise login/consent/device/logout/manage, collect violations, flip to enforce)
- [ ] Configure a real Redis `IDistributedCache` before multi-replica deployment (current `AddDistributedMemoryCache` is single-node)

## Product quality
- [ ] WCAG 2.2 AA accessibility audit for both embedded UIs
- [ ] Localization (extract runtime copy, currently pt-BR hardcoded)
- [ ] SCIM: bulk, sorting, ETags (intentionally unadvertised — enable per demand)

## Forward-looking protocol work
- [ ] FAPI 2.0 Advancing Profile (requires encrypted request objects beyond JAR)
- [ ] Rich Authorization Requests (RAR — `authorization_details`)
- [ ] OpenID Federation (entity statements, trust chains)
- [ ] SSF durable outbox/retry state (persistent delivery guarantees beyond best-effort)
