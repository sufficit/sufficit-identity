START TRANSACTION;
CREATE TABLE `tokenmaintenance` (
    `id` int NOT NULL,
    `enabled` tinyint(1) NOT NULL,
    `retentiondays` int NOT NULL,
    `intervalminutes` int NOT NULL,
    `nextrunatutc` datetime(6) NOT NULL,
    `runrequested` tinyint(1) NOT NULL,
    `revision` varchar(36) CHARACTER SET utf8mb4 NOT NULL,
    `owner` varchar(128) CHARACTER SET utf8mb4 NULL,
    `leaseuntilutc` datetime(6) NULL,
    `currentrunid` varchar(36) CHARACTER SET utf8mb4 NULL,
    CONSTRAINT `PK_tokenmaintenance` PRIMARY KEY (`id`)
) CHARACTER SET=utf8mb4;

CREATE TABLE `tokenmaintenanceruns` (
    `id` varchar(36) CHARACTER SET utf8mb4 NOT NULL,
    `startedatutc` datetime(6) NOT NULL,
    `finishedatutc` datetime(6) NULL,
    `status` varchar(24) CHARACTER SET utf8mb4 NOT NULL,
    `tokens` bigint NOT NULL,
    `authorizations` bigint NOT NULL,
    `owner` varchar(128) CHARACTER SET utf8mb4 NOT NULL,
    CONSTRAINT `PK_tokenmaintenanceruns` PRIMARY KEY (`id`)
) CHARACTER SET=utf8mb4;

INSERT INTO `tokenmaintenance` (`id`, `currentrunid`, `enabled`, `intervalminutes`, `leaseuntilutc`, `nextrunatutc`, `owner`, `retentiondays`, `revision`, `runrequested`)
VALUES (1, NULL, FALSE, 360, NULL, TIMESTAMP '1970-01-01 00:00:00', NULL, 30, 'initial', FALSE);

CREATE INDEX `IX_tokenmaintenanceruns_startedatutc` ON `tokenmaintenanceruns` (`startedatutc`);

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
VALUES ('20261024204655_AddTokenMaintenance', '10.0.13');

COMMIT;

