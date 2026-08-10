# Legacy cutover — operational gates pending

> **Status:** NO-GO for production cutover. Database/provider gates are complete (see `202608011820-legacy-cutover-db-provider.md`). The items below are operational — they require human action against real infrastructure and clients, not code.

## Client gates
- [ ] Every active client has an assigned owner and documented final state
- [ ] Implicit/hybrid/password consumers migrated to authorization_code + PKCE or retired
- [ ] Confidential clients have newly issued credentials (post-migration)
- [ ] PKCE S256 enforced on every authorization-code client
- [ ] Redirect, logout and CORS allowlists verified per client
- [ ] Token format validated by every resource server (reference vs JWT)

## Key and infrastructure gates
- [ ] Signing/encryption key distribution tested end-to-end (PFX on every replica)
- [ ] JWKS overlap and rotation tested (old + new keys visible during transition)
- [ ] Proxy and forwarded headers verified end-to-end (X-Forwarded-Proto/Host, TrustedProxies)
- [ ] Management parity verified (or temporary legacy administration approved)

## Rehearsal gates
- [ ] Backup, cutover and rollback rehearsals complete and recorded
- [ ] No migration step depends on secrets in source control (gitleaks clean)
