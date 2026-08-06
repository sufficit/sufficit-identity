-- ==========================================================================
-- 081-add-ssf-streams-and-vault-keys.sql
-- Brings databases that pre-date the SSF stream and internal vault features
-- to the current schema. Safe to re-run on MariaDB 10.4.
-- ============================================================================

START TRANSACTION;

CREATE TABLE IF NOT EXISTS `ssfsetdeliveries` (
    `id`              BIGINT        NOT NULL AUTO_INCREMENT,
    `streamid`        VARCHAR(64)   CHARACTER SET utf8mb4 NOT NULL,
    `jti`             VARCHAR(64)   CHARACTER SET utf8mb4 NOT NULL,
    `setpayload`      LONGTEXT      CHARACTER SET utf8mb4 NOT NULL,
    `createdatutc`    DATETIME(6)   NOT NULL,
    `consumedat`      DATETIME(6)   NULL,
    PRIMARY KEY (`id`),
    KEY `IX_ssfsetdeliveries_jti` (`jti`),
    KEY `IX_ssfsetdeliveries_streamid_consumedat` (`streamid`, `consumedat`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `ssfstreams` (
    `id`               VARCHAR(64)   CHARACTER SET utf8mb4 NOT NULL,
    `streamid`         VARCHAR(64)   CHARACTER SET utf8mb4 NOT NULL,
    `audience`         VARCHAR(256)  CHARACTER SET utf8mb4 NOT NULL,
    `deliverymethod`   VARCHAR(32)   CHARACTER SET utf8mb4 NOT NULL,
    `endpoint`         VARCHAR(512)  CHARACTER SET utf8mb4 NULL,
    `authorization`    LONGTEXT      CHARACTER SET utf8mb4 NULL,
    `status`           VARCHAR(16)   CHARACTER SET utf8mb4 NOT NULL,
    `verificationstate` VARCHAR(16)  CHARACTER SET utf8mb4 NOT NULL,
    `subjectscope`     VARCHAR(512)  CHARACTER SET utf8mb4 NOT NULL,
    `eventsrequested`  VARCHAR(1024) CHARACTER SET utf8mb4 NOT NULL,
    `description`      VARCHAR(256)  CHARACTER SET utf8mb4 NULL,
    `createdatutc`     DATETIME(6)   NOT NULL,
    `updatedatutc`     DATETIME(6)   NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `AK_ssfstreams_streamid` (`streamid`),
    KEY `IX_ssfstreams_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- The first SSF migration used varchar(512); the current model permits the
-- encrypted authorization value to be longtext. This is harmless if already
-- applied and keeps older partial installations compatible.
ALTER TABLE `ssfstreams`
    MODIFY COLUMN `authorization` LONGTEXT CHARACTER SET utf8mb4 NULL;

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
SELECT '20260805202819_AddSsfStreams', '10.0.10'
WHERE NOT EXISTS (
    SELECT 1 FROM `__sufficit_identity_migrations`
    WHERE `MigrationId` = '20260805202819_AddSsfStreams'
);

CREATE TABLE IF NOT EXISTS `vaultkeys` (
    `id`          BIGINT       NOT NULL AUTO_INCREMENT,
    `keyname`     VARCHAR(64)  CHARACTER SET utf8mb4 NOT NULL,
    `keyversion`  INT          NOT NULL,
    `purpose`     VARCHAR(16)  CHARACTER SET utf8mb4 NOT NULL,
    `wrappedkey`  LONGBLOB     NOT NULL,
    `createdatutc` DATETIME(6) NOT NULL,
    `retiredatutc` DATETIME(6) NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `AK_vaultkeys_keyname_keyversion` (`keyname`, `keyversion`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
SELECT '20260806162913_AddVaultKeys', '10.0.10'
WHERE NOT EXISTS (
    SELECT 1 FROM `__sufficit_identity_migrations`
    WHERE `MigrationId` = '20260806162913_AddVaultKeys'
);

COMMIT;
