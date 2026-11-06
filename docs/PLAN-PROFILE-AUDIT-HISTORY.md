# Profile audit history

## Objective and constraints

Record changed profile fields before/after an administrative update and retrieve
older audit events by resource and UTC interval with bounded, stable pagination.
Keep the existing list API compatible. Require `identity.audit.read`; never
serialize credentials or entire user entities. Retain the existing retention policy.
No production account changes or deployment are part of this implementation.

## Ordered checkpoints

1. Completed — Reviewed RFC 9110 §§17.8–17.9, RFC 9700 §4.9.3 and the existing authorization/retention boundaries.
2. Completed — Implemented snapshots and POST search; both initial regression tests failed before and passed after.
3. Completed — 97 tests passed, zero warnings; Markdown reachability and git diff --check passed. Permanent API/security documentation written.
4. **In progress** — Review/stage only task files, commit and push to main; verify remote state.

## Acceptance and validation

- Changed fields have exact old/new values, unchanged fields and secrets are absent.
- No-op, rejected and rolled-back updates do not produce successful change snapshots.
- Authorized queries reach old rows; resource/date filters and equal-timestamp page
  boundaries do not skip or repeat rows. Invalid cursors/intervals are rejected.
- Unauthorized readers remain denied; legacy list clients retain their response shape.
- Run the relevant xUnit tests through `dotnet test src/tests/Sufficit.Identity.Tests.csproj`,
  Markdown coverage and `git diff --check`.

## Review evidence

Initial tree clean on main. Existing audit storage has BeforeJson/AfterJson and
resource/time indexes. Current list endpoint returns at most 250 newest rows.
RFC/security review and exact validation results will be recorded at delivery.

## Blocker

None.

Decision: add POST `/api/audit/search` with JSON filters, `(OccurredAtUtc, Id)` cursor and 1–250 page size. Keep GET list unchanged; mark audit responses no-store. Capture only changed profile fields and confirmation side effects in the same transaction. Existing default retention is 15 days.

Validation checkpoint: 88 focused tests passed, zero warnings (profiles, audit search, retention, management UI compatibility and legacy list). Additional timestamp-boundary coverage and documentation checks pending.
