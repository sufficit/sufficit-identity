CREATE TABLE IF NOT EXISTS `__sufficit_identity_migrations` (
    `MigrationId` varchar(150) CHARACTER SET utf8mb4 NOT NULL,
    `ProductVersion` varchar(32) CHARACTER SET utf8mb4 NOT NULL,
    CONSTRAINT `PK___sufficit_identity_migrations` PRIMARY KEY (`MigrationId`)
) CHARACTER SET=utf8mb4;

START TRANSACTION;
ALTER DATABASE CHARACTER SET utf8mb4;

CREATE TABLE `applications` (
    `id` varchar(100) CHARACTER SET utf8mb4 NOT NULL,
    `application_type` varchar(50) CHARACTER SET utf8mb4 NULL,
    `client_id` varchar(100) CHARACTER SET utf8mb4 NULL,
    `client_secret` longtext CHARACTER SET utf8mb4 NULL,
    `client_type` varchar(50) CHARACTER SET utf8mb4 NULL,
    `concurrency_token` varchar(50) CHARACTER SET utf8mb4 NULL,
    `consent_type` varchar(50) CHARACTER SET utf8mb4 NULL,
    `display_name` longtext CHARACTER SET utf8mb4 NULL,
    `display_names` longtext CHARACTER SET utf8mb4 NULL,
    `json_web_key_set` longtext CHARACTER SET utf8mb4 NULL,
    `permissions` longtext CHARACTER SET utf8mb4 NULL,
    `post_logout_redirect_uris` longtext CHARACTER SET utf8mb4 NULL,
    `properties` longtext CHARACTER SET utf8mb4 NULL,
    `redirect_uris` longtext CHARACTER SET utf8mb4 NULL,
    `requirements` longtext CHARACTER SET utf8mb4 NULL,
    `settings` longtext CHARACTER SET utf8mb4 NULL,
    CONSTRAINT `PK_applications` PRIMARY KEY (`id`)
) CHARACTER SET=utf8mb4;

CREATE TABLE `dataprotectionkeys` (
    `id` int NOT NULL AUTO_INCREMENT,
    `friendlyname` longtext CHARACTER SET utf8mb4 NULL,
    `xml` longtext CHARACTER SET utf8mb4 NULL,
    CONSTRAINT `PK_dataprotectionkeys` PRIMARY KEY (`id`)
) CHARACTER SET=utf8mb4;

CREATE TABLE `roles` (
    `id` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `name` varchar(256) CHARACTER SET utf8mb4 NULL,
    `normalizedname` varchar(256) CHARACTER SET utf8mb4 NULL,
    `concurrencystamp` longtext CHARACTER SET utf8mb4 NULL,
    CONSTRAINT `PK_roles` PRIMARY KEY (`id`)
) CHARACTER SET=utf8mb4;

CREATE TABLE `scopes` (
    `id` varchar(100) CHARACTER SET utf8mb4 NOT NULL,
    `concurrency_token` varchar(50) CHARACTER SET utf8mb4 NULL,
    `description` longtext CHARACTER SET utf8mb4 NULL,
    `descriptions` longtext CHARACTER SET utf8mb4 NULL,
    `display_name` longtext CHARACTER SET utf8mb4 NULL,
    `display_names` longtext CHARACTER SET utf8mb4 NULL,
    `name` varchar(200) CHARACTER SET utf8mb4 NULL,
    `properties` longtext CHARACTER SET utf8mb4 NULL,
    `resources` longtext CHARACTER SET utf8mb4 NULL,
    CONSTRAINT `PK_scopes` PRIMARY KEY (`id`)
) CHARACTER SET=utf8mb4;

CREATE TABLE `userpasskeys` (
    `credentialid` varbinary(1024) NOT NULL,
    `userid` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `publickey` longblob NOT NULL,
    `name` longtext CHARACTER SET utf8mb4 NULL,
    `createdat` datetime(6) NOT NULL,
    `signcount` int unsigned NOT NULL,
    `transports` longtext CHARACTER SET utf8mb4 NOT NULL,
    `isuserverified` tinyint(1) NOT NULL,
    `isbackupeligible` tinyint(1) NOT NULL,
    `isbackedup` tinyint(1) NOT NULL,
    `attestationobject` longblob NOT NULL,
    `clientdatajson` longblob NOT NULL,
    CONSTRAINT `PK_userpasskeys` PRIMARY KEY (`credentialid`)
) CHARACTER SET=utf8mb4;

CREATE TABLE `users` (
    `id` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `timestamp` timestamp NOT NULL DEFAULT (UTC_TIMESTAMP()) ON UPDATE CURRENT_TIMESTAMP(),
    `username` varchar(256) CHARACTER SET utf8mb4 NULL,
    `normalizedusername` varchar(256) CHARACTER SET utf8mb4 NULL,
    `email` varchar(256) CHARACTER SET utf8mb4 NULL,
    `normalizedemail` varchar(256) CHARACTER SET utf8mb4 NULL,
    `emailconfirmed` tinyint(1) NOT NULL,
    `passwordhash` longtext CHARACTER SET utf8mb4 NULL,
    `securitystamp` longtext CHARACTER SET utf8mb4 NULL,
    `concurrencystamp` longtext CHARACTER SET utf8mb4 NULL,
    `phonenumber` longtext CHARACTER SET utf8mb4 NULL,
    `phonenumberconfirmed` tinyint(1) NOT NULL,
    `twofactorenabled` tinyint(1) NOT NULL,
    `lockoutend` datetime(6) NULL,
    `lockoutenabled` tinyint(1) NOT NULL,
    `accessfailedcount` int NOT NULL,
    CONSTRAINT `PK_users` PRIMARY KEY (`id`)
) CHARACTER SET=utf8mb4;

CREATE TABLE `authorizations` (
    `id` varchar(100) CHARACTER SET utf8mb4 NOT NULL,
    `application_id` varchar(100) CHARACTER SET utf8mb4 NULL,
    `concurrency_token` varchar(50) CHARACTER SET utf8mb4 NULL,
    `creation_date` datetime(6) NULL,
    `properties` longtext CHARACTER SET utf8mb4 NULL,
    `scopes` longtext CHARACTER SET utf8mb4 NULL,
    `status` varchar(50) CHARACTER SET utf8mb4 NULL,
    `subject` varchar(400) CHARACTER SET utf8mb4 NULL,
    `type` varchar(50) CHARACTER SET utf8mb4 NULL,
    CONSTRAINT `PK_authorizations` PRIMARY KEY (`id`),
    CONSTRAINT `FK_authorizations_applications_application_id` FOREIGN KEY (`application_id`) REFERENCES `applications` (`id`)
) CHARACTER SET=utf8mb4;

CREATE TABLE `roleclaims` (
    `id` int NOT NULL AUTO_INCREMENT,
    `roleid` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `claimtype` longtext CHARACTER SET utf8mb4 NULL,
    `claimvalue` longtext CHARACTER SET utf8mb4 NULL,
    CONSTRAINT `PK_roleclaims` PRIMARY KEY (`id`),
    CONSTRAINT `FK_roleclaims_roles_roleid` FOREIGN KEY (`roleid`) REFERENCES `roles` (`id`) ON DELETE CASCADE
) CHARACTER SET=utf8mb4;

CREATE TABLE `userclaims` (
    `id` int NOT NULL AUTO_INCREMENT,
    `userid` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `claimtype` longtext CHARACTER SET utf8mb4 NULL,
    `claimvalue` longtext CHARACTER SET utf8mb4 NULL,
    CONSTRAINT `PK_userclaims` PRIMARY KEY (`id`),
    CONSTRAINT `FK_userclaims_users_userid` FOREIGN KEY (`userid`) REFERENCES `users` (`id`) ON DELETE CASCADE
) CHARACTER SET=utf8mb4;

CREATE TABLE `userlogins` (
    `loginprovider` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `providerkey` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `providerdisplayname` longtext CHARACTER SET utf8mb4 NULL,
    `userid` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    CONSTRAINT `PK_userlogins` PRIMARY KEY (`loginprovider`, `providerkey`),
    CONSTRAINT `FK_userlogins_users_userid` FOREIGN KEY (`userid`) REFERENCES `users` (`id`) ON DELETE CASCADE
) CHARACTER SET=utf8mb4;

CREATE TABLE `userroles` (
    `userid` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `roleid` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    CONSTRAINT `PK_userroles` PRIMARY KEY (`userid`, `roleid`),
    CONSTRAINT `FK_userroles_roles_roleid` FOREIGN KEY (`roleid`) REFERENCES `roles` (`id`) ON DELETE CASCADE,
    CONSTRAINT `FK_userroles_users_userid` FOREIGN KEY (`userid`) REFERENCES `users` (`id`) ON DELETE CASCADE
) CHARACTER SET=utf8mb4;

CREATE TABLE `usertokens` (
    `userid` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `loginprovider` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `name` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `value` longtext CHARACTER SET utf8mb4 NULL,
    CONSTRAINT `PK_usertokens` PRIMARY KEY (`userid`, `loginprovider`, `name`),
    CONSTRAINT `FK_usertokens_users_userid` FOREIGN KEY (`userid`) REFERENCES `users` (`id`) ON DELETE CASCADE
) CHARACTER SET=utf8mb4;

CREATE TABLE `tokens` (
    `id` varchar(100) CHARACTER SET utf8mb4 NOT NULL,
    `application_id` varchar(100) CHARACTER SET utf8mb4 NULL,
    `authorization_id` varchar(100) CHARACTER SET utf8mb4 NULL,
    `concurrency_token` varchar(50) CHARACTER SET utf8mb4 NULL,
    `creation_date` datetime(6) NULL,
    `expiration_date` datetime(6) NULL,
    `payload` longtext CHARACTER SET utf8mb4 NULL,
    `properties` longtext CHARACTER SET utf8mb4 NULL,
    `redemption_date` datetime(6) NULL,
    `reference_id` varchar(100) CHARACTER SET utf8mb4 NULL,
    `status` varchar(50) CHARACTER SET utf8mb4 NULL,
    `subject` varchar(400) CHARACTER SET utf8mb4 NULL,
    `type` varchar(150) CHARACTER SET utf8mb4 NULL,
    CONSTRAINT `PK_tokens` PRIMARY KEY (`id`),
    CONSTRAINT `FK_tokens_applications_application_id` FOREIGN KEY (`application_id`) REFERENCES `applications` (`id`),
    CONSTRAINT `FK_tokens_authorizations_authorization_id` FOREIGN KEY (`authorization_id`) REFERENCES `authorizations` (`id`)
) CHARACTER SET=utf8mb4;

CREATE UNIQUE INDEX `AK_OpenIddictApplications_ClientId` ON `applications` (`client_id`);

CREATE INDEX `IX_OpenIddictAuthorizations_ApplicationId_Status_Subject_Type` ON `authorizations` (`application_id`, `status`, `subject`, `type`);

CREATE INDEX `IX_roleclaims_roleid` ON `roleclaims` (`roleid`);

CREATE UNIQUE INDEX `RoleNameIndex` ON `roles` (`normalizedname`);

CREATE UNIQUE INDEX `AK_OpenIddictScopes_Name` ON `scopes` (`name`);

CREATE UNIQUE INDEX `AK_OpenIddictTokens_ReferenceId` ON `tokens` (`reference_id`);

CREATE INDEX `IX_OpenIddictTokens_ApplicationId_Status_Subject_Type` ON `tokens` (`application_id`, `status`, `subject`, `type`);

CREATE INDEX `IX_OpenIddictTokens_AuthorizationId` ON `tokens` (`authorization_id`);

CREATE INDEX `IX_userclaims_userid` ON `userclaims` (`userid`);

CREATE INDEX `IX_userlogins_userid` ON `userlogins` (`userid`);

CREATE INDEX `IX_userpasskeys_userid` ON `userpasskeys` (`userid`);

CREATE INDEX `IX_userroles_roleid` ON `userroles` (`roleid`);

CREATE INDEX `EmailIndex` ON `users` (`normalizedemail`);

CREATE UNIQUE INDEX `UserNameIndex` ON `users` (`normalizedusername`);

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
VALUES ('20260726213918_Initial', '10.0.10');

COMMIT;

START TRANSACTION;
CREATE TABLE `brandingthemes` (
    `id` int NOT NULL AUTO_INCREMENT,
    `name` varchar(100) CHARACTER SET utf8mb4 NOT NULL,
    `isactive` tinyint(1) NOT NULL,
    `logourl` varchar(512) CHARACTER SET utf8mb4 NULL,
    `faviconurl` varchar(512) CHARACTER SET utf8mb4 NULL,
    `headericonurl` varchar(512) CHARACTER SET utf8mb4 NULL,
    `backgroundimageurl` varchar(512) CHARACTER SET utf8mb4 NULL,
    `brandcolor` varchar(7) CHARACTER SET utf8mb4 NULL,
    `brandhovercolor` varchar(7) CHARACTER SET utf8mb4 NULL,
    `brandsoftcolor` varchar(7) CHARACTER SET utf8mb4 NULL,
    `themecolor` varchar(7) CHARACTER SET utf8mb4 NULL,
    `title` varchar(200) CHARACTER SET utf8mb4 NULL,
    `brandname` varchar(100) CHARACTER SET utf8mb4 NULL,
    `brandsubtitle` varchar(100) CHARACTER SET utf8mb4 NULL,
    `createdat` datetime(6) NOT NULL,
    `updatedat` datetime(6) NOT NULL,
    CONSTRAINT `PK_brandingthemes` PRIMARY KEY (`id`)
) CHARACTER SET=utf8mb4;

CREATE INDEX `IX_brandingthemes_isactive` ON `brandingthemes` (`isactive`);

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
VALUES ('20260729025623_AddBrandingThemes', '10.0.10');

COMMIT;

START TRANSACTION;
ALTER TABLE `brandingthemes` ADD `avatarurltemplate` varchar(512) CHARACTER SET utf8mb4 NULL;

CREATE TABLE `managementauditevents` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `occurredatutc` datetime(6) NOT NULL,
    `operatorsubject` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `operatordisplayname` varchar(255) CHARACTER SET utf8mb4 NULL,
    `capability` varchar(150) CHARACTER SET utf8mb4 NOT NULL,
    `resourcetype` varchar(100) CHARACTER SET utf8mb4 NOT NULL,
    `resourceid` varchar(255) CHARACTER SET utf8mb4 NULL,
    `contextid` varchar(255) CHARACTER SET utf8mb4 NULL,
    `authorizationoutcome` varchar(50) CHARACTER SET utf8mb4 NOT NULL,
    `operationoutcome` varchar(50) CHARACTER SET utf8mb4 NOT NULL,
    `reasoncode` varchar(100) CHARACTER SET utf8mb4 NULL,
    `correlationid` varchar(100) CHARACTER SET utf8mb4 NOT NULL,
    `authenticationmethods` varchar(255) CHARACTER SET utf8mb4 NULL,
    CONSTRAINT `PK_managementauditevents` PRIMARY KEY (`id`)
) CHARACTER SET=utf8mb4;

CREATE INDEX `IX_managementauditevents_occurredatutc` ON `managementauditevents` (`occurredatutc`);

CREATE INDEX `IX_managementauditevents_resource` ON `managementauditevents` (`resourcetype`, `resourceid`);

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
VALUES ('20260729221512_AddManagementAuditEvents', '10.0.10');

COMMIT;

START TRANSACTION;
CREATE TABLE `scimgroups` (
    `id` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `externalid` varchar(255) CHARACTER SET utf8mb4 NULL,
    `displayname` varchar(256) CHARACTER SET utf8mb4 NOT NULL,
    `createdatutc` datetime(6) NOT NULL,
    `updatedatutc` datetime(6) NOT NULL,
    `concurrencystamp` varchar(64) CHARACTER SET utf8mb4 NOT NULL,
    CONSTRAINT `PK_scimgroups` PRIMARY KEY (`id`)
) CHARACTER SET=utf8mb4;

CREATE TABLE `scimuserprofiles` (
    `userid` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `externalid` varchar(255) CHARACTER SET utf8mb4 NULL,
    `displayname` varchar(256) CHARACTER SET utf8mb4 NULL,
    `formattedname` varchar(256) CHARACTER SET utf8mb4 NULL,
    `familyname` varchar(256) CHARACTER SET utf8mb4 NULL,
    `givenname` varchar(256) CHARACTER SET utf8mb4 NULL,
    `middlename` varchar(256) CHARACTER SET utf8mb4 NULL,
    `honorificprefix` varchar(256) CHARACTER SET utf8mb4 NULL,
    `honorificsuffix` varchar(256) CHARACTER SET utf8mb4 NULL,
    `title` varchar(256) CHARACTER SET utf8mb4 NULL,
    `usertype` varchar(256) CHARACTER SET utf8mb4 NULL,
    `preferredlanguage` varchar(35) CHARACTER SET utf8mb4 NULL,
    `locale` varchar(35) CHARACTER SET utf8mb4 NULL,
    `timezone` varchar(100) CHARACTER SET utf8mb4 NULL,
    `createdatutc` datetime(6) NOT NULL,
    `updatedatutc` datetime(6) NOT NULL,
    CONSTRAINT `PK_scimuserprofiles` PRIMARY KEY (`userid`),
    CONSTRAINT `FK_scimuserprofiles_users_userid` FOREIGN KEY (`userid`) REFERENCES `users` (`id`) ON DELETE CASCADE
) CHARACTER SET=utf8mb4;

CREATE TABLE `scimgroupgroupmembers` (
    `groupid` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `membergroupid` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    CONSTRAINT `PK_scimgroupgroupmembers` PRIMARY KEY (`groupid`, `membergroupid`),
    CONSTRAINT `FK_scimgroupgroupmembers_scimgroups_groupid` FOREIGN KEY (`groupid`) REFERENCES `scimgroups` (`id`) ON DELETE CASCADE,
    CONSTRAINT `FK_scimgroupgroupmembers_scimgroups_membergroupid` FOREIGN KEY (`membergroupid`) REFERENCES `scimgroups` (`id`) ON DELETE RESTRICT
) CHARACTER SET=utf8mb4;

CREATE TABLE `scimgroupusermembers` (
    `groupid` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `userid` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    CONSTRAINT `PK_scimgroupusermembers` PRIMARY KEY (`groupid`, `userid`),
    CONSTRAINT `FK_scimgroupusermembers_scimgroups_groupid` FOREIGN KEY (`groupid`) REFERENCES `scimgroups` (`id`) ON DELETE CASCADE,
    CONSTRAINT `FK_scimgroupusermembers_users_userid` FOREIGN KEY (`userid`) REFERENCES `users` (`id`) ON DELETE CASCADE
) CHARACTER SET=utf8mb4;

CREATE INDEX `IX_scimgroupgroupmembers_membergroupid` ON `scimgroupgroupmembers` (`membergroupid`);

CREATE INDEX `IX_scimgroups_displayname` ON `scimgroups` (`displayname`);

CREATE INDEX `IX_scimgroups_externalid` ON `scimgroups` (`externalid`);

CREATE INDEX `IX_scimgroupusermembers_userid` ON `scimgroupusermembers` (`userid`);

CREATE INDEX `IX_scimuserprofiles_externalid` ON `scimuserprofiles` (`externalid`);

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
VALUES ('20260730220100_AddScimProvisioning', '10.0.10');

COMMIT;

START TRANSACTION;
ALTER TABLE `users` ADD `createdatutc` datetime(6) NULL;

UPDATE `users` SET `createdatutc` = `timestamp` WHERE `createdatutc` IS NULL;

ALTER TABLE `users` MODIFY COLUMN `createdatutc` datetime(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6));

CREATE INDEX `IX_users_createdatutc` ON `users` (`createdatutc`);

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
VALUES ('20260804020337_AddUserCreatedAtUtc', '10.0.10');

COMMIT;

START TRANSACTION;
CREATE TABLE `ssfsetdeliveries` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `streamid` varchar(64) CHARACTER SET utf8mb4 NOT NULL,
    `jti` varchar(64) CHARACTER SET utf8mb4 NOT NULL,
    `setpayload` longtext CHARACTER SET utf8mb4 NOT NULL,
    `createdatutc` datetime(6) NOT NULL,
    `consumedat` datetime(6) NULL,
    CONSTRAINT `PK_ssfsetdeliveries` PRIMARY KEY (`id`)
) CHARACTER SET=utf8mb4;

CREATE TABLE `ssfstreams` (
    `id` varchar(64) CHARACTER SET utf8mb4 NOT NULL,
    `streamid` varchar(64) CHARACTER SET utf8mb4 NOT NULL,
    `audience` varchar(256) CHARACTER SET utf8mb4 NOT NULL,
    `deliverymethod` varchar(32) CHARACTER SET utf8mb4 NOT NULL,
    `endpoint` varchar(512) CHARACTER SET utf8mb4 NULL,
    `authorization` varchar(512) CHARACTER SET utf8mb4 NULL,
    `status` varchar(16) CHARACTER SET utf8mb4 NOT NULL,
    `verificationstate` varchar(16) CHARACTER SET utf8mb4 NOT NULL,
    `subjectscope` varchar(512) CHARACTER SET utf8mb4 NOT NULL,
    `eventsrequested` varchar(1024) CHARACTER SET utf8mb4 NOT NULL,
    `description` varchar(256) CHARACTER SET utf8mb4 NULL,
    `createdatutc` datetime(6) NOT NULL,
    `updatedatutc` datetime(6) NOT NULL,
    CONSTRAINT `PK_ssfstreams` PRIMARY KEY (`id`)
) CHARACTER SET=utf8mb4;

CREATE INDEX `IX_ssfsetdeliveries_jti` ON `ssfsetdeliveries` (`jti`);

CREATE INDEX `IX_ssfsetdeliveries_streamid_consumedat` ON `ssfsetdeliveries` (`streamid`, `consumedat`);

CREATE UNIQUE INDEX `AK_ssfstreams_streamid` ON `ssfstreams` (`streamid`);

CREATE INDEX `IX_ssfstreams_status` ON `ssfstreams` (`status`);

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
VALUES ('20260805202819_AddSsfStreams', '10.0.10');

COMMIT;

START TRANSACTION;
CREATE TABLE `oidcusersessions` (
    `id` bigint NOT NULL AUTO_INCREMENT,
    `sessionid` varchar(64) CHARACTER SET utf8mb4 NOT NULL,
    `subject` varchar(400) CHARACTER SET utf8mb4 NOT NULL,
    `remoteipaddress` varchar(64) CHARACTER SET utf8mb4 NULL,
    `useragent` varchar(512) CHARACTER SET utf8mb4 NULL,
    `createdatutc` datetime(6) NOT NULL,
    `lastactivityutc` datetime(6) NOT NULL,
    `expiresutc` datetime(6) NULL,
    `protectedticket` longblob NOT NULL,
    CONSTRAINT `PK_oidcusersessions` PRIMARY KEY (`id`)
) CHARACTER SET=utf8mb4;

CREATE UNIQUE INDEX `AK_oidcusersessions_sessionid` ON `oidcusersessions` (`sessionid`);

CREATE INDEX `IX_oidcusersessions_expiresutc` ON `oidcusersessions` (`expiresutc`);

CREATE INDEX `IX_oidcusersessions_subject` ON `oidcusersessions` (`subject`);

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
VALUES ('20260806131249_AddOidcUserSessions', '10.0.10');

COMMIT;

