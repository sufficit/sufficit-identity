# Browsertest production browser validation — 2026-09-06

## Purpose

Enable and run the authenticated browser suite (Playwright/NUnit) against
production (`https://identity.sufficit.com.br`) by provisioning the dedicated
`browsertest` account referenced by `ManagementConsoleHealthTests`, closing the
known gap recorded on 2026-09-05 ("suíte autenticada não roda em produção pois o
usuário browsertest não existe lá").

## Provisioning

- Direct idempotent `INSERT` into the Galera cluster through `eveo-apps`
  (`users` table; write on a single node, replication confirmed on all three:
  eveo-apps, apoint-apps, castrum-apps).
- Account id `f1df09b4-86f2-4176-898a-c9beac6064ad`, username `browsertest`,
  `emailconfirmed=1` (required by `SignIn.RequireConfirmedEmail=true`),
  `twofactorenabled=0`, `lockoutenabled=1`, no roles, no claims — least
  privilege by construction.
- Password hash in canonical ASP.NET Core Identity V3 format
  (`0x01 | prf=2 | iter=100000 | saltLen=16` big-endian, HMAC-SHA512, 64-byte
  subkey, 124 base64 chars). A first draft using a little-endian layout was
  detected and corrected via `UPDATE` **before** any login attempt; the account
  recorded zero failed accesses (`accessfailedcount=0`, no lockout) throughout.
- The plaintext password was only ever passed inline via
  `SUFFICIT_TEST_PASSWORD` to the test process; it is not stored in this
  repository, in memory, or in any file.

## Verification

Three runs of:

```
SUFFICIT_TEST_BASE_URL=https://identity.sufficit.com.br \
SUFFICIT_TEST_USER=browsertest \
SUFFICIT_TEST_PASSWORD=*** \
dotnet test src/tests/Sufficit.Identity.BrowserTests --filter ManagementConsoleHealthTests
```

- **Runs 1–2 (pre-hardening): 5/8 passed, 3 failed** — all three failures share one root cause: the suite's
  `AuthenticateAsync` setup probes `POST /__test__/signin`, which exists only in
  Development. In production it answers 404, which the console/resource
  collectors register as an error. This is a test-harness limitation in
  non-Development environments, not a product defect; the test's own comments
  already anticipate that page-level checks run against the MFA gate instead.
- **The real login flow works**: the form-based password login (with antiforgery
  token) was exercised both by Playwright (8 sessions) and by a raw curl flow —
  `302 → /vault` — proving the provisioned hash verifies under the production
  PBKDF2 hasher and that the application cookie is issued.
- Authenticated authorization behaves fail-closed for this least-privilege
  account: `/vault` renders **200** authenticated, `/vault/admin` and
  `/management/` redirect to `accessdenied` (no scope, no MFA evidence — by
  design), and `/api/vault/*` remains 401 for anonymous access.
- No lockout side effects after the whole run: `accessfailedcount=0`,
  `lockoutend IS NULL` on all three nodes.
- **Run 3 (post-hardening): 8/8 passed** against production after attaching the
  `ConsoleCollector` in `AuthenticateAsync` only *after* the optional
  `/__test__/signin` probe, so the expected 404/`ERR_ABORTED` on non-Development
  hosts no longer reaches the per-page checks.
  `Clients_page_has_no_console_errors`, `Dashboard_has_no_console_errors` and
  `Users_page_has_no_failed_resources` now pass unchanged against production.

## Teardown

After the successful 8/8 run the account was removed to end its exposure:

- `DELETE FROM users WHERE normalizedusername='BROWSERTEST' AND
  id='f1df09b4-86f2-4176-898a-c9beac6064ad'` executed through `eveo-apps`;
  replication confirmed — `COUNT(*)=0` on eveo-apps, apoint-apps and
  castrum-apps; no orphan `userroles` rows.
- Post-removal login attempt against production returns
  `302 → /account/login?error=invalid_credentials`, as expected.

## Findings

1. RESOLVED in this activity: the `/__test__/signin` probe noise on
   non-Development hosts was eliminated by moving the console-collector
   attachment after the probe in `ManagementConsoleHealthTests.AuthenticateAsync`.
   The probe itself is kept: on Development it still upgrades the session, and
   its failure was already non-fatal by design.
2. `app.css`/`users.css` rule-count warnings reproduce in production (the known
   SUI `styles/ @import` issue), matching the Development behavior — no
   regression.

## Follow-ups

- [x] Harden `ManagementConsoleHealthTests` for non-Development targets
      (finding 1) — done; 8/8 validated in production.
- [x] Remove the `browsertest` account — done the same day (see Teardown);
      this record is kept for audit.
