# Administrative profile audit history

## Delivered behavior

Profile changes now record the old/new values of changed username, e-mail,
phone and their confirmation flags, in the same transaction as the update.
An explicit allowlist excludes credentials and unchanged personal data. Failed,
rolled-back and no-op updates do not carry successful change snapshots.

The additive `POST /api/audit/search` API searches retained history by resource
and UTC interval, using timestamp/ID cursor pagination with 1–250 rows per page.
Every page demands `identity.audit.read`. Filters stay in the JSON body, and
both audit endpoints return no-store. The existing GET array contract is preserved.
No schema migration, production-account change or deployment was performed.

Contract, limits and RFC/security review:
[Administrative profile audit history](../management/USAGE-AUDIT-HISTORY.md).
The review covered RFC 9110 §§17.8–17.9 and RFC 9700 §4.9.3. Existing retention
(default 15 days) still applies. Historical snapshots cannot be reconstructed.

## Validation

- Regression baseline: 2 failures, expected: missing search endpoint (404) and
  missing profile snapshot (null). Both passed after implementation.
- Final focused suite: **97 tests passed, 0 warnings**, covering profile changes,
  failed/rejected/no-op changes, authorization, UTC offsets and date bounds,
  timestamp ties, concurrent inserts during pagination, invalid cursors/filters,
  page limits, retention, legacy list, embedded UI compatibility and Markdown coverage.
- Command: `dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore --filter
  'FullyQualifiedName~UserManagementControllerTests|FullyQualifiedName~ManagementAuditSearchTests|FullyQualifiedName~ManagementAuditVolumeTests|FullyQualifiedName~ManagementUiRoutingTests|FullyQualifiedName~ClientsControllerTests.Audit_endpoint|FullyQualifiedName~MarkdownCoverageTests'
  --nologo --verbosity quiet` (local SUI).
- Package-mode locked restore: 14 projects, zero errors/warnings. Generated
  local-SUI lockfile differences were reviewed and restored; no dependency changes.
- `git diff --check` passed. Tests used SQLite/in-process HTTP, not production.

## Delivery

Implementation commit `a8709fd` was pushed to `origin/main` successfully
(`aa6fefc..a8709fd`). The completed temporary plan was retired after push;
its durable contract and validation evidence are preserved here and in the usage guide.
Deployment remains separate and was not performed.
