-- ============================================================================
-- 083-enforce-normalized-email-uniqueness.sql
-- Report duplicate normalized emails without returning addresses, then fail
-- closed until an operator resolves every collision. The unique index is
-- additive and permits multiple NULL values, preserving legacy accounts that
-- do not have an email address.
-- ============================================================================

START TRANSACTION;

CREATE TEMPORARY TABLE `_identity_duplicate_email_report` AS
SELECT SHA2(`normalizedemail`, 256) AS `email_hash`, COUNT(*) AS `account_count`
FROM `users`
WHERE `normalizedemail` IS NOT NULL
GROUP BY `normalizedemail`
HAVING COUNT(*) > 1;

SELECT `email_hash`, `account_count`
FROM `_identity_duplicate_email_report`
ORDER BY `email_hash`;

CREATE TEMPORARY TABLE `_identity_duplicate_email_guard` (
    `valid` TINYINT NOT NULL CHECK (`valid` = 1)
);
INSERT INTO `_identity_duplicate_email_guard` (`valid`)
SELECT IF((SELECT COUNT(*) FROM `_identity_duplicate_email_report`) = 0, 1, 0);

ALTER TABLE `users`
    ADD UNIQUE INDEX IF NOT EXISTS `UX_users_normalizedemail`
        (`normalizedemail`);

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
SELECT '20260808_EnforceNormalizedEmailUniqueness', '10.0.10'
WHERE NOT EXISTS (
    SELECT 1 FROM `__sufficit_identity_migrations`
    WHERE `MigrationId` = '20260808_EnforceNormalizedEmailUniqueness'
);

COMMIT;
