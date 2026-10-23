-- Migration UniqueNormalizedEmail (plan F9), and the brandingthemes drift found
-- by the schema comparison of 2026-10-23 (plan F8). Apply BEFORE deploying the
-- binaries; safe with the previous ones. Supersedes 083.
--
-- 1. Refuse while any normalized email belongs to more than one account
--    (report shows hashes, never addresses). NULL emails stay allowed.
START TRANSACTION;

CREATE TEMPORARY TABLE `_identity_duplicate_email_report` AS
SELECT SHA2(`normalizedemail`, 256) AS `email_hash`, COUNT(*) AS `account_count`
FROM `users`
WHERE `normalizedemail` IS NOT NULL
GROUP BY `normalizedemail`
HAVING COUNT(*) > 1;

SELECT `email_hash`, `account_count` FROM `_identity_duplicate_email_report` ORDER BY `email_hash`;

CREATE TEMPORARY TABLE `_identity_duplicate_email_guard` (
    `valid` TINYINT NOT NULL CHECK (`valid` = 1)
);
INSERT INTO `_identity_duplicate_email_guard` (`valid`)
SELECT IF(COUNT(*) = 0, 1, 0) FROM `_identity_duplicate_email_report`;

ALTER TABLE `users` DROP INDEX `EmailIndex`;
CREATE UNIQUE INDEX `EmailIndex` ON `users` (`normalizedemail`);

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
VALUES ('20261023124342_UniqueNormalizedEmail', '10.0.13');

COMMIT;

-- 2. brandingthemes was created in production before 050 existed, with
--    second-precision timestamps and a default the model does not have.
--    Idempotent: a no-op where the table already matches.
ALTER TABLE `brandingthemes`
    MODIFY `createdat` datetime(6) NOT NULL,
    MODIFY `updatedat` datetime(6) NOT NULL,
    ALTER COLUMN `isactive` DROP DEFAULT;
