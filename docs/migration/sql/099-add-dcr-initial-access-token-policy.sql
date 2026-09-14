-- Optional per-token grant type and scope limits for DCR initial access tokens.
-- Additive; apply once, before deploying the corresponding application binaries.
START TRANSACTION;
ALTER TABLE `dcrinitialaccesstokens` ADD `allowedgranttypesjson` varchar(2048) CHARACTER SET utf8mb4 NULL;

ALTER TABLE `dcrinitialaccesstokens` ADD `allowedscopesjson` varchar(2048) CHARACTER SET utf8mb4 NULL;

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
VALUES ('20260914151128_AddDcrInitialAccessTokenPolicy', '10.0.11');

COMMIT;

