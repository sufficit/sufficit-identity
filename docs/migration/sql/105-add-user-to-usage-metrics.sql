-- Migration AddUserToUsageMetrics: the user becomes one more dimension of the
-- daily usage aggregate (empty when there is none), so one table serves usage
-- per application and per user. Safe with the previous binaries (they insert
-- the default); apply before deploying.
START TRANSACTION;
ALTER TABLE `identityapplicationusagedaily` DROP INDEX `IX_identityusagedaily_key`;

ALTER TABLE `identityapplicationusagedaily` ADD `userid` varchar(64) CHARACTER SET utf8mb4 NOT NULL DEFAULT '';

CREATE UNIQUE INDEX `IX_identityusagedaily_key` ON `identityapplicationusagedaily` (`day`, `node`, `clientid`, `eventtype`, `endpointtype`, `granttype`, `outcome`, `userid`);

CREATE INDEX `IX_identityusagedaily_userid_day` ON `identityapplicationusagedaily` (`userid`, `day`);

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
VALUES ('20261022144056_AddUserToUsageMetrics', '10.0.13');

COMMIT;
