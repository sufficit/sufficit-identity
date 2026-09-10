-- Trusted proxy configuration and before/after administrative audit values.
-- Apply once, before deploying the corresponding application binaries.
START TRANSACTION;
ALTER TABLE `managementauditevents` ADD `afterjson` longtext CHARACTER SET utf8mb4 NULL;

ALTER TABLE `managementauditevents` ADD `beforejson` longtext CHARACTER SET utf8mb4 NULL;

CREATE TABLE `trustedproxyconfiguration` (
    `id` int NOT NULL,
    `networksjson` longtext CHARACTER SET utf8mb4 NOT NULL,
    `forwardlimit` int NULL,
    `revision` varchar(36) CHARACTER SET utf8mb4 NOT NULL,
    `updatedatutc` datetime(6) NOT NULL,
    CONSTRAINT `PK_trustedproxyconfiguration` PRIMARY KEY (`id`)
) CHARACTER SET=utf8mb4;

INSERT INTO `trustedproxyconfiguration` (`id`, `forwardlimit`, `networksjson`, `revision`, `updatedatutc`)
VALUES (1, NULL, '[]', 'initial', TIMESTAMP '1970-01-01 00:00:00');

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
VALUES ('20260910131719_AddTrustedProxyConfiguration', '10.0.11');

COMMIT;

