-- ============================================================================
-- 082-add-security-hardening-state.sql
-- Additive coverage for migrations after 081. Safe to re-run on MariaDB 10.4.
-- Apply after 081 on installations that already have the legacy Identity
-- tables. Fresh installs already contain these objects in 001-create-empty-
-- database.sql; the migration-history inserts below make the two paths agree.
-- ============================================================================

START TRANSACTION;

CREATE TABLE IF NOT EXISTS `identityapplicationusageevents` (
    `id` BIGINT NOT NULL AUTO_INCREMENT,
    `occurredatutc` DATETIME(6) NOT NULL,
    `clientid` VARCHAR(255) CHARACTER SET utf8mb4 NOT NULL,
    `eventtype` VARCHAR(64) CHARACTER SET utf8mb4 NOT NULL,
    `endpointtype` VARCHAR(64) CHARACTER SET utf8mb4 NOT NULL,
    `granttype` VARCHAR(100) CHARACTER SET utf8mb4 NULL,
    `outcome` VARCHAR(32) CHARACTER SET utf8mb4 NOT NULL,
    `subjecthash` VARCHAR(64) CHARACTER SET utf8mb4 NULL,
    PRIMARY KEY (`id`),
    KEY `IX_identityusage_clientid_occurredatutc` (`clientid`, `occurredatutc`),
    KEY `IX_identityusage_eventtype_occurredatutc` (`eventtype`, `occurredatutc`),
    KEY `IX_identityusage_occurredatutc` (`occurredatutc`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `identitymetricsconfiguration` (
    `id` INT NOT NULL,
    `enabled` TINYINT(1) NOT NULL,
    `retentiondays` INT NOT NULL,
    `exportenabled` TINYINT(1) NOT NULL,
    `provider` VARCHAR(50) CHARACTER SET utf8mb4 NOT NULL,
    `endpoint` VARCHAR(1024) CHARACTER SET utf8mb4 NULL,
    `database` VARCHAR(255) CHARACTER SET utf8mb4 NULL,
    `authorizationscheme` VARCHAR(32) CHARACTER SET utf8mb4 NULL,
    `username` VARCHAR(255) CHARACTER SET utf8mb4 NULL,
    `secretciphertext` LONGTEXT CHARACTER SET utf8mb4 NULL,
    `timeoutseconds` INT NOT NULL,
    `batchsize` INT NOT NULL,
    `updatedatutc` DATETIME(6) NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `identitymetricsconfiguration`
    (`id`, `enabled`, `retentiondays`, `exportenabled`, `provider`,
     `timeoutseconds`, `batchsize`, `updatedatutc`)
SELECT 1, 1, 90, 0, 'internal', 10, 250, UTC_TIMESTAMP(6)
WHERE NOT EXISTS (
    SELECT 1 FROM `identitymetricsconfiguration` WHERE `id` = 1
);

-- Hardened SSF ownership/challenge columns. MariaDB supports IF NOT EXISTS
-- for ADD COLUMN, which keeps this script safe during rolling upgrades.
ALTER TABLE `ssfstreams`
    ADD COLUMN IF NOT EXISTS `ownerclientid` VARCHAR(100) CHARACTER SET utf8mb4 NULL,
    ADD COLUMN IF NOT EXISTS `verificationchallengehash` VARCHAR(43) CHARACTER SET utf8mb4 NULL,
    ADD COLUMN IF NOT EXISTS `verificationexpiresatutc` DATETIME(6) NULL;
ALTER TABLE `ssfsetdeliveries`
    ADD COLUMN IF NOT EXISTS `deliverykey` VARCHAR(64) CHARACTER SET utf8mb4 NULL;
UPDATE `ssfstreams`
SET `ownerclientid` = `audience`
WHERE `ownerclientid` IS NULL;
ALTER TABLE `ssfstreams`
    ADD INDEX IF NOT EXISTS `IX_ssfstreams_ownerclientid_status` (`ownerclientid`, `status`);
ALTER TABLE `ssfsetdeliveries`
    ADD UNIQUE INDEX IF NOT EXISTS `AK_ssfsetdeliveries_deliverykey` (`deliverykey`);

CREATE TABLE IF NOT EXISTS `cibapendingstates` (
    `authreqid` VARCHAR(64) CHARACTER SET utf8mb4 NOT NULL,
    `clientid` VARCHAR(100) CHARACTER SET utf8mb4 NOT NULL,
    `subject` VARCHAR(400) CHARACTER SET utf8mb4 NOT NULL,
    `scopesjson` VARCHAR(2048) CHARACTER SET utf8mb4 NOT NULL,
    `bindingmessage` VARCHAR(180) CHARACTER SET utf8mb4 NULL,
    `expiresatutc` DATETIME(6) NOT NULL,
    `createdatutc` DATETIME(6) NOT NULL,
    `lastpollatutc` DATETIME(6) NOT NULL,
    `approvedsubject` VARCHAR(400) CHARACTER SET utf8mb4 NULL,
    `state` VARCHAR(16) CHARACTER SET utf8mb4 NOT NULL,
    `consumptionid` VARCHAR(64) CHARACTER SET utf8mb4 NULL,
    PRIMARY KEY (`authreqid`),
    UNIQUE KEY `AK_cibapendingstates_consumptionid` (`consumptionid`),
    KEY `IX_cibapendingstates_state_expiresatutc` (`state`, `expiresatutc`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `dpopreplayentries` (
    `key` VARCHAR(64) CHARACTER SET utf8mb4 NOT NULL,
    `expiresatutc` DATETIME(6) NOT NULL,
    PRIMARY KEY (`key`),
    KEY `IX_dpopreplayentries_expiresatutc` (`expiresatutc`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `managementclientdrafts` (
    `id` CHAR(36) COLLATE ascii_general_ci NOT NULL,
    `ownersubject` VARCHAR(255) CHARACTER SET utf8mb4 NOT NULL,
    `profile` VARCHAR(40) CHARACTER SET utf8mb4 NOT NULL,
    `currentstep` VARCHAR(32) CHARACTER SET utf8mb4 NOT NULL,
    `status` VARCHAR(24) CHARACTER SET utf8mb4 NOT NULL,
    `protectedpayload` LONGTEXT CHARACTER SET utf8mb4 NOT NULL,
    `version` VARCHAR(32) CHARACTER SET utf8mb4 NOT NULL,
    `createdclientid` VARCHAR(100) CHARACTER SET utf8mb4 NULL,
    `createdatutc` DATETIME(6) NOT NULL,
    `updatedatutc` DATETIME(6) NOT NULL,
    `expiresatutc` DATETIME(6) NOT NULL,
    PRIMARY KEY (`id`),
    KEY `IX_managementclientdrafts_expiresatutc` (`expiresatutc`),
    KEY `IX_managementclientdrafts_owner_status_updated`
        (`ownersubject`, `status`, `updatedatutc`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
SELECT '20260807020859_AddIdentityApplicationMetrics', '10.0.10'
WHERE NOT EXISTS (SELECT 1 FROM `__sufficit_identity_migrations`
                  WHERE `MigrationId` = '20260807020859_AddIdentityApplicationMetrics');
INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
SELECT '20260807135147_HardenSsfStreams', '10.0.10'
WHERE NOT EXISTS (SELECT 1 FROM `__sufficit_identity_migrations`
                  WHERE `MigrationId` = '20260807135147_HardenSsfStreams');
INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
SELECT '20260807140821_AddAtomicProtocolState', '10.0.10'
WHERE NOT EXISTS (SELECT 1 FROM `__sufficit_identity_migrations`
                  WHERE `MigrationId` = '20260807140821_AddAtomicProtocolState');
INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
SELECT '20260807161036_AddManagementClientDrafts', '10.0.10'
WHERE NOT EXISTS (SELECT 1 FROM `__sufficit_identity_migrations`
                  WHERE `MigrationId` = '20260807161036_AddManagementClientDrafts');

COMMIT;
