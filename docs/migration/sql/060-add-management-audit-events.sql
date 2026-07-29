-- ============================================================================
-- 060-add-management-audit-events.sql
-- Adds the append-only administrative audit table and the branding avatar
-- column that became part of the canonical UI model after the branding table
-- was introduced. Repeated execution is safe on MariaDB 10.4.
-- ============================================================================

ALTER TABLE `brandingthemes`
    ADD COLUMN IF NOT EXISTS `avatarurltemplate` VARCHAR(512) NULL;

CREATE TABLE IF NOT EXISTS `managementauditevents` (
    `id`                    BIGINT AUTO_INCREMENT PRIMARY KEY,
    `occurredatutc`         DATETIME(6)  NOT NULL,
    `operatorsubject`       VARCHAR(255) NOT NULL,
    `operatordisplayname`   VARCHAR(255) NULL,
    `capability`             VARCHAR(150) NOT NULL,
    `resourcetype`           VARCHAR(100) NOT NULL,
    `resourceid`             VARCHAR(255) NULL,
    `contextid`              VARCHAR(255) NULL,
    `authorizationoutcome`   VARCHAR(50)  NOT NULL,
    `operationoutcome`       VARCHAR(50)  NOT NULL,
    `reasoncode`             VARCHAR(100) NULL,
    `correlationid`          VARCHAR(100) NOT NULL,
    `authenticationmethods`  VARCHAR(255) NULL,
    INDEX `IX_managementauditevents_occurredatutc` (`occurredatutc`),
    INDEX `IX_managementauditevents_resource` (`resourcetype`, `resourceid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
SELECT '20260729221512_AddManagementAuditEvents', '10.0.10'
WHERE NOT EXISTS (
    SELECT 1
    FROM `__sufficit_identity_migrations`
    WHERE `MigrationId` = '20260729221512_AddManagementAuditEvents'
);
