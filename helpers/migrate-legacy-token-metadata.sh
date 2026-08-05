#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  migrate-legacy-token-metadata.sh \
    --defaults-extra-file /protected/mariadb.cnf \
    --source-database legacy_identity \
    --target-database identity \
    [--apply]

The command is a read-only dry-run unless --apply is specified. It imports
only legacy reference-token identifiers and presentation metadata as revoked
OpenIddict tombstones. It never copies token payloads and never updates the
source database.
EOF
}

defaults_file=""
source_database=""
target_database=""
apply=false

while (($#)); do
    case "$1" in
        --defaults-extra-file)
            if (($# < 2)); then
                echo "missing value for $1" >&2
                exit 2
            fi
            defaults_file="${2:-}"
            shift 2
            ;;
        --source-database)
            if (($# < 2)); then
                echo "missing value for $1" >&2
                exit 2
            fi
            source_database="${2:-}"
            shift 2
            ;;
        --target-database)
            if (($# < 2)); then
                echo "missing value for $1" >&2
                exit 2
            fi
            target_database="${2:-}"
            shift 2
            ;;
        --apply)
            apply=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ ! -f "${defaults_file}" ]]; then
    echo "--defaults-extra-file must point to an existing protected file" >&2
    exit 2
fi
if [[ ! "${source_database}" =~ ^[A-Za-z0-9_]+$ ]]; then
    echo "invalid --source-database identifier" >&2
    exit 2
fi
if [[ ! "${target_database}" =~ ^[A-Za-z0-9_]+$ ]]; then
    echo "invalid --target-database identifier" >&2
    exit 2
fi
if [[ "${source_database}" == "${target_database}" ]]; then
    echo "source and target databases must be different" >&2
    exit 2
fi
if ! command -v mariadb >/dev/null 2>&1; then
    echo "mariadb client was not found" >&2
    exit 127
fi

db=(mariadb "--defaults-extra-file=${defaults_file}" --batch --skip-column-names)

read -r eligible described existing conflicts invalid_source <<<"$("${db[@]}" --execute="
SELECT
  (SELECT COUNT(*)
     FROM \`${source_database}\`.\`persistedgrants\` legacy
    WHERE legacy.\`type\` = 'reference_token'
      AND legacy.\`key\` IS NOT NULL
      AND CHAR_LENGTH(legacy.\`key\`) <= 100),
  (SELECT COUNT(*)
     FROM \`${source_database}\`.\`persistedgrants\` legacy
    WHERE legacy.\`type\` = 'reference_token'
      AND legacy.\`key\` IS NOT NULL
      AND CHAR_LENGTH(legacy.\`key\`) <= 100
      AND NULLIF(TRIM(legacy.\`description\`), '') IS NOT NULL),
  (SELECT COUNT(*)
     FROM \`${target_database}\`.\`tokens\`
    WHERE \`type\` = 'legacy_reference_token'),
  (SELECT COUNT(*)
     FROM \`${source_database}\`.\`persistedgrants\` legacy
     JOIN \`${target_database}\`.\`tokens\` target
       ON target.\`id\` = CONCAT('legacy-', legacy.\`id\`)
       OR target.\`reference_id\` = legacy.\`key\`
    WHERE legacy.\`type\` = 'reference_token'
      AND legacy.\`key\` IS NOT NULL
      AND CHAR_LENGTH(legacy.\`key\`) <= 100
      AND (target.\`id\` <> CONCAT('legacy-', legacy.\`id\`)
        OR target.\`reference_id\` <> legacy.\`key\`
        OR target.\`type\` <> 'legacy_reference_token')),
  (SELECT COUNT(*)
     FROM \`${source_database}\`.\`persistedgrants\` legacy
    WHERE legacy.\`type\` = 'reference_token'
      AND (legacy.\`key\` IS NULL OR CHAR_LENGTH(legacy.\`key\`) > 100));
")"

printf 'eligible=%s described=%s already_imported=%s conflicts=%s invalid_source=%s\n' \
    "${eligible}" "${described}" "${existing}" "${conflicts}" "${invalid_source}"

if ((conflicts > 0 || invalid_source > 0)); then
    echo "preflight failed; no data was changed" >&2
    exit 1
fi
if [[ "${apply}" != true ]]; then
    echo "dry-run only; rerun with --apply after taking a protected target backup"
    exit 0
fi

"${db[@]}" --execute="
START TRANSACTION;

INSERT INTO \`${target_database}\`.\`tokens\` (
    \`id\`, \`application_id\`, \`authorization_id\`, \`concurrency_token\`,
    \`creation_date\`, \`expiration_date\`, \`payload\`, \`properties\`,
    \`redemption_date\`, \`reference_id\`, \`status\`, \`subject\`, \`type\`
)
SELECT
    CONCAT('legacy-', legacy.\`id\`), NULL, NULL, NULL,
    legacy.\`creationtime\`, legacy.\`expiration\`, NULL,
    JSON_OBJECT(
        'urn:sufficit:token:client_id', NULLIF(TRIM(legacy.\`clientid\`), ''),
        'urn:sufficit:token:description', CASE
            WHEN NULLIF(TRIM(legacy.\`description\`), '') IS NULL THEN NULL
            WHEN legacy.\`description\` LIKE '[identity-upgrade] %' THEN LEFT(
                TRIM(SUBSTRING(
                    legacy.\`description\`,
                    CHAR_LENGTH('[identity-upgrade] ') + 1)),
                250)
            ELSE LEFT(TRIM(legacy.\`description\`), 250)
        END,
        'sufficit:migration', JSON_OBJECT(
            'source', 'duende',
            'legacyId', legacy.\`id\`,
            'legacyClientId', legacy.\`clientid\`,
            'requiresRegeneration', TRUE
        )
    ),
    COALESCE(legacy.\`consumedtime\`, UTC_TIMESTAMP(6)),
    legacy.\`key\`, 'revoked', legacy.\`subjectid\`, 'legacy_reference_token'
FROM \`${source_database}\`.\`persistedgrants\` legacy
WHERE legacy.\`type\` = 'reference_token'
  AND legacy.\`key\` IS NOT NULL
  AND CHAR_LENGTH(legacy.\`key\`) <= 100
ON DUPLICATE KEY UPDATE
    \`payload\` = IF(
        \`tokens\`.\`type\` = 'legacy_reference_token',
        NULL,
        \`tokens\`.\`payload\`),
    \`properties\` = IF(
        \`tokens\`.\`type\` = 'legacy_reference_token',
        VALUES(\`properties\`),
        \`tokens\`.\`properties\`),
    \`status\` = IF(
        \`tokens\`.\`type\` = 'legacy_reference_token',
        'revoked',
        \`tokens\`.\`status\`),
    \`redemption_date\` = IF(
        \`tokens\`.\`type\` = 'legacy_reference_token',
        COALESCE(\`tokens\`.\`redemption_date\`, UTC_TIMESTAMP(6)),
        \`tokens\`.\`redemption_date\`);

COMMIT;
"

read -r imported imported_descriptions unsafe <<<"$("${db[@]}" --execute="
SELECT
  COUNT(*),
  COALESCE(SUM(
    JSON_VALUE(\`properties\`, '$.\"urn:sufficit:token:description\"') IS NOT NULL), 0),
  COALESCE(SUM(
    \`status\` <> 'revoked' OR \`payload\` IS NOT NULL OR \`redemption_date\` IS NULL), 0)
FROM \`${target_database}\`.\`tokens\`
WHERE \`type\` = 'legacy_reference_token';
")"

printf 'imported=%s imported_descriptions=%s unsafe=%s\n' \
    "${imported}" "${imported_descriptions}" "${unsafe}"
if [[ "${imported}" != "${eligible}" || "${unsafe}" != "0" ]]; then
    echo "post-import verification failed" >&2
    exit 1
fi
