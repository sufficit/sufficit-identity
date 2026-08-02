-- Preserve only the identifiers needed by account-management APIs after the
-- Duende -> OpenIddict cutover. These rows are tombstones, never credentials:
-- no payload, serialized grant data, session identifier or usable token is
-- copied, and every row is created with the revoked status.
--
-- Re-executable: the deterministic OpenIddict id is based on the legacy
-- numeric primary key. The unique reference_id also keeps the identifier that
-- existing Sufficit account screens use to name a reference token.
INSERT INTO `tokens` (
    `id`,
    `application_id`,
    `authorization_id`,
    `concurrency_token`,
    `creation_date`,
    `expiration_date`,
    `payload`,
    `properties`,
    `redemption_date`,
    `reference_id`,
    `status`,
    `subject`,
    `type`
)
SELECT
    CONCAT('legacy-', legacy.`id`),
    NULL,
    NULL,
    NULL,
    legacy.`creationtime`,
    legacy.`expiration`,
    NULL,
    JSON_OBJECT(
        'sufficit:migration', JSON_OBJECT(
            'source', 'duende',
            'legacyId', legacy.`id`,
            'legacyClientId', legacy.`clientid`,
            'requiresRegeneration', TRUE
        )
    ),
    COALESCE(legacy.`consumedtime`, UTC_TIMESTAMP(6)),
    legacy.`key`,
    'revoked',
    legacy.`subjectid`,
    'legacy_reference_token'
FROM `persistedgrants` legacy
WHERE legacy.`type` = 'reference_token'
  AND legacy.`key` IS NOT NULL
  AND CHAR_LENGTH(legacy.`key`) <= 100
ON DUPLICATE KEY UPDATE
    `payload` = NULL,
    `status` = 'revoked',
    `redemption_date` = COALESCE(`tokens`.`redemption_date`, UTC_TIMESTAMP(6)),
    `type` = 'legacy_reference_token';

-- Invalidate the original reference-token rows as part of the same cutover.
-- They remain queryable during the compatibility window so existing account
-- APIs do not lose identifiers, but the legacy issuer can no longer accept
-- them. The stable prefix is presentation metadata, not a credential value.
UPDATE `persistedgrants`
SET `consumedtime` = COALESCE(`consumedtime`, UTC_TIMESTAMP(6)),
    `description` = LEFT(
        CONCAT(
            '[identity-upgrade] ',
            COALESCE(`description`, '')
        ),
        200
    )
WHERE `type` = 'reference_token'
  AND `key` IS NOT NULL
  AND CHAR_LENGTH(`key`) <= 100
  AND COALESCE(`description`, '') NOT LIKE '[identity-upgrade] %';
