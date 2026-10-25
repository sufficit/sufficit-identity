# Atomic token pruning for replicated databases

The maintenance sweep previously committed token deletion and authorization
deletion separately. A parallel replication receiver could apply the parent
DELETE before the child DELETE completed, fail the foreign key check and leave
the cluster as inconsistent.

The sweep now uses transactions of at most 100 tokens. Existing orphaned
eligible authorizations are handled first. Each token batch also deletes the
newly orphaned eligible parents before committing, so the final child deletion
and the parent deletion belong to one writeset. Transactions are retried through
the provider execution strategy; failures roll back the current batch. Previous
batches remain committed, and the success file is still written only when the
whole sweep succeeds. Both phases are capped at 10,000 batches.

Eligibility preserves OpenIddict 7.7.2's retention, status, authorization and
expiration predicates. Valid unexpired tokens on valid authorizations, including
entries without expiration, stay protected; inactive unexpired entries stay too.
Foreign key enforcement remains enabled.

Validation:

- New regression failed with the original service on SQLite and MariaDB 10.4.34:
  the last child and its parent were observed in separate commits.
- After the fix, 101 selected tests passed with zero warnings, including pruning,
  token stores and maintenance commands, architecture and Markdown coverage.
- Regression checks every commit across a chain longer than two batches,
  enforces the 100-token limit and tests rollback by failing the final commit.
  Both SQLite and an isolated local MariaDB container execute the contract.
- Tests force `SufficitUseLocalSui=false`, matching package-based deployment;
  the sibling UI checkout otherwise conflicts with package-restored assets.
- An isolated, configuration-free maintenance release can be installed alongside
  an API release. The scheduler's WorkingDirectory and ExecStart must target that
  release and inherit the existing production configuration. No HTTP listener or
  hosted application worker is started by `--prune-tokens`.

These tests verify transaction boundaries and SQL-provider behavior. They do not
reproduce parallel apply scheduling on a multi-node Galera cluster. Keep any
operational serialization mitigation until that workload is separately validated.

Operational contract: [centralized pruning runbook](../operations/RUNBOOK-TOKEN-PRUNING.md).
