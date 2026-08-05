#!/bin/bash
set -euo pipefail

# Rehearses the additive legacy cutover against a logical backup that was
# already copied to this MariaDB host. Never points at the source database.
#
# Usage (on an isolated database host or the DB host using disposable schemas):
#   MARIADB_SOCKET=/path/to/mysql.sock ./rehearse-real-backup.sh backup.sql.gz 3

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DUMP_PATH="${1:?Path to a gzip-compressed logical backup is required}"
ITERATIONS="${2:-3}"
DB_SOCKET="${MARIADB_SOCKET:-/var/run/mysqld/mysqld.sock}"
DB_USER="${MARIADB_USER:-root}"
RUN_TOKEN="${BASHPID}"

if [[ ! "${ITERATIONS}" =~ ^[1-9][0-9]*$ ]] || (( ITERATIONS > 10 )); then
    echo "iterations must be an integer between 1 and 10" >&2
    exit 2
fi

if [[ ! -f "${DUMP_PATH}" ]]; then
    echo "backup file not found: ${DUMP_PATH}" >&2
    exit 2
fi

gzip -t "${DUMP_PATH}"
if [[ "$(gzip -dc "${DUMP_PATH}" | grep -c '^CREATE TABLE')" -ne 39 ]]; then
    echo "backup does not contain the expected 39-table legacy schema" >&2
    exit 2
fi

DB=(mariadb --no-defaults --protocol=socket --socket="${DB_SOCKET}" --user="${DB_USER}")
CREATED_DATABASES=()

cleanup() {
    local database
    for database in "${CREATED_DATABASES[@]:-}"; do
        if [[ "${database}" =~ ^identity_rehearsal_[0-9]+_[0-9]+$ ]]; then
            "${DB[@]}" --execute="DROP DATABASE IF EXISTS \`${database}\`;"
        fi
    done
}
trap cleanup EXIT

require_equal() {
    local label="$1"
    local expected="$2"
    local actual="$3"
    if [[ "${expected}" != "${actual}" ]]; then
        echo "${label} mismatch: expected '${expected}', got '${actual}'" >&2
        exit 1
    fi
}

schema_fingerprint() {
    local database="$1"
    "${DB[@]}" --batch --skip-column-names "${database}" <<'SQL'
SET SESSION group_concat_max_len = 16777216;
SELECT SHA2(GROUP_CONCAT(
    CONCAT_WS('|', table_name, ordinal_position, column_name, column_type,
        is_nullable, COALESCE(column_default, '<NULL>'), extra)
    ORDER BY table_name, ordinal_position SEPARATOR '\n'), 256)
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name IN (
      'users','roles','roleclaims','userclaims','userlogins','userroles',
      'usertokens','userpasskeys','dataprotectionkeys');
SELECT SHA2(GROUP_CONCAT(
    CONCAT_WS('|', table_name, index_name, seq_in_index, column_name,
        non_unique, index_type)
    ORDER BY table_name, index_name, seq_in_index SEPARATOR '\n'), 256)
FROM information_schema.statistics
WHERE table_schema = DATABASE()
  AND table_name IN (
      'users','roles','roleclaims','userclaims','userlogins','userroles',
      'usertokens','userpasskeys','dataprotectionkeys');
SELECT SHA2(GROUP_CONCAT(
    CONCAT_WS('|', table_name, constraint_name, column_name,
        COALESCE(referenced_table_name, ''), COALESCE(referenced_column_name, ''))
    ORDER BY table_name, constraint_name, ordinal_position SEPARATOR '\n'), 256)
FROM information_schema.key_column_usage
WHERE table_schema = DATABASE()
  AND table_name IN (
      'users','roles','roleclaims','userclaims','userlogins','userroles',
      'usertokens','userpasskeys','dataprotectionkeys');
SQL
}

shared_row_counts() {
    local database="$1"
    "${DB[@]}" --batch --skip-column-names "${database}" --execute="
        SELECT CONCAT_WS('|',
            (SELECT COUNT(*) FROM users),
            (SELECT COUNT(*) FROM roles),
            (SELECT COUNT(*) FROM roleclaims),
            (SELECT COUNT(*) FROM userclaims),
            (SELECT COUNT(*) FROM userlogins),
            (SELECT COUNT(*) FROM userroles),
            (SELECT COUNT(*) FROM usertokens),
            (SELECT COUNT(*) FROM userpasskeys),
            (SELECT COUNT(*) FROM dataprotectionkeys));"
}

refresh_fingerprint() {
    local database="$1"
    "${DB[@]}" --batch --skip-column-names "${database}" --execute="
        SELECT CONCAT_WS('|', COUNT(*), COALESCE(BIT_XOR(CRC32(CONCAT_WS('|',
            id, \`key\`, type, COALESCE(consumedtime, ''),
            COALESCE(description, ''), COALESCE(data, '')))), 0))
        FROM persistedgrants WHERE type = 'refresh_token';"
}

for ((iteration = 1; iteration <= ITERATIONS; iteration++)); do
    echo "iteration ${iteration}/${ITERATIONS}: restoring fresh backup"
    database="identity_rehearsal_${RUN_TOKEN}_${iteration}"
    if [[ ! "${database}" =~ ^identity_rehearsal_[0-9]+_[0-9]+$ ]]; then
        echo "refusing unsafe rehearsal database name: ${database}" >&2
        exit 2
    fi
    CREATED_DATABASES+=("${database}")

    "${DB[@]}" --execute="CREATE DATABASE \`${database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;"
    gzip -dc "${DUMP_PATH}" | "${DB[@]}" "${database}"

    preflight_output="$("${DB[@]}" --batch --skip-column-names "${database}" \
        < "${SCRIPT_DIR}/010-preflight-legacy.sql")"
    if [[ -n "${preflight_output}" ]]; then
        echo "preflight failed in iteration ${iteration}:" >&2
        echo "${preflight_output}" >&2
        exit 1
    fi

    before_schema="$(schema_fingerprint "${database}")"
    before_rows="$(shared_row_counts "${database}")"
    before_refresh="$(refresh_fingerprint "${database}")"
    eligible_references="$("${DB[@]}" --batch --skip-column-names "${database}" --execute="
        SELECT COUNT(*) FROM persistedgrants
        WHERE type = 'reference_token' AND \`key\` IS NOT NULL
          AND CHAR_LENGTH(\`key\`) <= 100;")"

    "${DB[@]}" "${database}" < "${SCRIPT_DIR}/011-add-openiddict-to-legacy.sql"
    "${DB[@]}" "${database}" < "${SCRIPT_DIR}/012-preserve-legacy-reference-token-identifiers.sql"
    # Prove the token-ID preservation step is idempotent.
    "${DB[@]}" "${database}" < "${SCRIPT_DIR}/012-preserve-legacy-reference-token-identifiers.sql"
    "${DB[@]}" "${database}" < "${SCRIPT_DIR}/050-add-branding-themes.sql"
    "${DB[@]}" "${database}" < "${SCRIPT_DIR}/060-add-management-audit-events.sql"
    "${DB[@]}" "${database}" < "${SCRIPT_DIR}/070-add-scim-provisioning.sql"

    after_schema="$(schema_fingerprint "${database}")"
    after_rows="$(shared_row_counts "${database}")"
    after_refresh="$(refresh_fingerprint "${database}")"

    require_equal "shared schema" "${before_schema}" "${after_schema}"
    require_equal "shared row counts" "${before_rows}" "${after_rows}"
    require_equal "refresh-token fingerprint" "${before_refresh}" "${after_refresh}"

    verification="$("${DB[@]}" --batch --skip-column-names "${database}" --execute="
        SELECT CONCAT_WS('|',
            (SELECT COUNT(*) FROM __sufficit_identity_migrations),
            (SELECT COUNT(*) FROM tokens WHERE type = 'legacy_reference_token'),
            (SELECT COUNT(*) FROM tokens WHERE type = 'legacy_reference_token'
                AND (status <> 'revoked' OR payload IS NOT NULL)),
            (SELECT COUNT(*) FROM persistedgrants
                WHERE type = 'reference_token' AND \`key\` IS NOT NULL
                  AND CHAR_LENGTH(\`key\`) <= 100
                  AND (consumedtime IS NULL OR description NOT LIKE '[identity-upgrade] %')),
            (SELECT COUNT(*) FROM information_schema.tables
                WHERE table_schema = DATABASE()));")"

    IFS='|' read -r migration_count tombstone_count invalid_tombstones \
        invalid_legacy_references table_count <<< "${verification}"
    require_equal "migration count" "4" "${migration_count}"
    require_equal "tombstone count" "${eligible_references}" "${tombstone_count}"
    require_equal "invalid tombstones" "0" "${invalid_tombstones}"
    require_equal "invalid legacy references" "0" "${invalid_legacy_references}"
    require_equal "table count" "50" "${table_count}"

    echo "iteration ${iteration}: ok (tables=${table_count}, migrations=${migration_count}, tombstones=${tombstone_count})"
    "${DB[@]}" --execute="DROP DATABASE \`${database}\`;"
    CREATED_DATABASES=()
done

echo "rehearsal complete: ${ITERATIONS} fresh restores passed"
