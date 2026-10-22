-- Phase 1 of migration AggregateUsageMetrics: the daily usage aggregate
-- (one row per UTC day, node and dimension; each node writes only its own).
-- Safe with the previous binaries. Apply BEFORE deploying the binaries; apply
-- 104 right AFTER they run on every node.
START TRANSACTION;
CREATE TABLE `identityapplicationusagedaily` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `day` date NOT NULL,
    `node` varchar(64) CHARACTER SET utf8mb4 NOT NULL,
    `clientid` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `eventtype` varchar(64) CHARACTER SET utf8mb4 NOT NULL,
    `endpointtype` varchar(64) CHARACTER SET utf8mb4 NOT NULL,
    `granttype` varchar(100) CHARACTER SET utf8mb4 NOT NULL,
    `outcome` varchar(32) CHARACTER SET utf8mb4 NOT NULL,
    `count` bigint NOT NULL,
    `lastoccurredatutc` datetime(6) NOT NULL,
    CONSTRAINT `PK_identityapplicationusagedaily` PRIMARY KEY (`id`)
) CHARACTER SET=utf8mb4;

CREATE INDEX `IX_identityusagedaily_clientid_day` ON `identityapplicationusagedaily` (`clientid`, `day`);

CREATE UNIQUE INDEX `IX_identityusagedaily_key` ON `identityapplicationusagedaily` (`day`, `node`, `clientid`, `eventtype`, `endpointtype`, `granttype`, `outcome`);

COMMIT;
