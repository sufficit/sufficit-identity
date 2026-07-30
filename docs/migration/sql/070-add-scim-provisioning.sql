-- ============================================================================
-- 070-add-scim-provisioning.sql
-- Adds the SCIM profile and group store without reusing ASP.NET Identity roles.
-- Repeated execution is safe on MariaDB 10.4.
-- ============================================================================

CREATE TABLE IF NOT EXISTS `scimgroups` (
    `id`                VARCHAR(255) NOT NULL,
    `externalid`        VARCHAR(255) NULL,
    `displayname`       VARCHAR(256) NOT NULL,
    `createdatutc`      DATETIME(6)  NOT NULL,
    `updatedatutc`      DATETIME(6)  NOT NULL,
    `concurrencystamp`  VARCHAR(64)  NOT NULL,
    PRIMARY KEY (`id`),
    INDEX `IX_scimgroups_displayname` (`displayname`),
    INDEX `IX_scimgroups_externalid` (`externalid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `scimuserprofiles` (
    `userid`              VARCHAR(255) NOT NULL,
    `externalid`          VARCHAR(255) NULL,
    `displayname`         VARCHAR(256) NULL,
    `formattedname`       VARCHAR(256) NULL,
    `familyname`          VARCHAR(256) NULL,
    `givenname`           VARCHAR(256) NULL,
    `middlename`          VARCHAR(256) NULL,
    `honorificprefix`     VARCHAR(256) NULL,
    `honorificsuffix`     VARCHAR(256) NULL,
    `title`               VARCHAR(256) NULL,
    `usertype`            VARCHAR(256) NULL,
    `preferredlanguage`   VARCHAR(35)  NULL,
    `locale`              VARCHAR(35)  NULL,
    `timezone`            VARCHAR(100) NULL,
    `createdatutc`        DATETIME(6)  NOT NULL,
    `updatedatutc`        DATETIME(6)  NOT NULL,
    PRIMARY KEY (`userid`),
    INDEX `IX_scimuserprofiles_externalid` (`externalid`),
    CONSTRAINT `FK_scimuserprofiles_users_userid`
        FOREIGN KEY (`userid`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `scimgroupgroupmembers` (
    `groupid`        VARCHAR(255) NOT NULL,
    `membergroupid`  VARCHAR(255) NOT NULL,
    PRIMARY KEY (`groupid`, `membergroupid`),
    INDEX `IX_scimgroupgroupmembers_membergroupid` (`membergroupid`),
    CONSTRAINT `FK_scimgroupgroupmembers_scimgroups_groupid`
        FOREIGN KEY (`groupid`) REFERENCES `scimgroups` (`id`)
        ON DELETE CASCADE,
    CONSTRAINT `FK_scimgroupgroupmembers_scimgroups_membergroupid`
        FOREIGN KEY (`membergroupid`) REFERENCES `scimgroups` (`id`)
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `scimgroupusermembers` (
    `groupid`  VARCHAR(255) NOT NULL,
    `userid`   VARCHAR(255) NOT NULL,
    PRIMARY KEY (`groupid`, `userid`),
    INDEX `IX_scimgroupusermembers_userid` (`userid`),
    CONSTRAINT `FK_scimgroupusermembers_scimgroups_groupid`
        FOREIGN KEY (`groupid`) REFERENCES `scimgroups` (`id`)
        ON DELETE CASCADE,
    CONSTRAINT `FK_scimgroupusermembers_users_userid`
        FOREIGN KEY (`userid`) REFERENCES `users` (`id`)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
SELECT '20260730220100_AddScimProvisioning', '10.0.10'
WHERE NOT EXISTS (
    SELECT 1
    FROM `__sufficit_identity_migrations`
    WHERE `MigrationId` = '20260730220100_AddScimProvisioning'
);
