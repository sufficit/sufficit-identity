# Legacy cutover — DB/provider gates completed

**Date:** 2026-07-22 → 2026-08-02
**Originally:** `docs/plans/PLAN-LEGACY-CUTOVER.md` (database/provider section, all done)

## Completed items

### Database and provider gates
- ✅ MariaDB/EF Core 10/Pomelo fork provider combination selected and SHA-256-verified in CI
- ✅ Shared table mapping explicit (`AppDbContext.OnModelCreating`)
- ✅ Migration history isolated (`__sufficit_identity_migrations`)
- ✅ Empty-database SQL reproducible (`docs/migration/sql/001-create-empty-database.sql`, schema-contract-tested)
- ✅ Additive legacy SQL fail-fast
- ✅ Schema-only MariaDB rehearsal automated (`MariaDbMigrationIntegrationTests`, `MariaDbGrantSmokeTests`)
- ✅ Real-backup rehearsal repeatably green (3 fresh restores 2026-08-02)

### Old token/refresh policy
- ✅ Reauth + revoked tombstones policy approved and implemented
- ✅ Token metadata preserved across regeneration (`PersonalTokensController`)
