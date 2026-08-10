# Pluggable UI — Phase 0 + Phase 1 completed

**Date:** 2026-08-01
**Originally:** `docs/plans/PLAN-PLUGGABLE-USER-INTERFACES.md` (phases 0-1, all done)

## Completed items

### Phase 0 — decouple registration
- ✅ Neutral hosting options (`IdentityUiHostingOptions` with Embedded/None modes)
- ✅ Register/map each official UI only in Embedded mode
- ✅ Composition executable serves discovery/health with both surfaces None (CI smoke-tested)
- ✅ Preserve current default deployment behavior (Embedded is the compatibility default)

### Phase 1 — neutral application contracts
- ✅ `Sufficit.Identity.Application.Abstractions` created (NuGet-packable)
- ✅ Public/account contracts moved without behavior change
- ✅ Management contracts split from OpenIddict/EF implementations
- ✅ Both official UIs depend only on abstractions + ASP.NET presentation primitives
- ✅ Architecture-enforcement tests prevent layering leaks (`ManagementUiArchitectureTests`)
