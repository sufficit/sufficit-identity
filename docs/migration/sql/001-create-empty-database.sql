CREATE TABLE IF NOT EXISTS `__sufficit_identity_migrations` (
    `MigrationId` varchar(150) NOT NULL,
    `ProductVersion` varchar(32) NOT NULL,
    PRIMARY KEY (`MigrationId`)
);

START TRANSACTION;
CREATE TABLE `applications` (
    `id` varchar(100) NOT NULL,
    `application_type` varchar(50) NULL,
    `client_id` varchar(100) NULL,
    `client_secret` longtext NULL,
    `client_type` varchar(50) NULL,
    `concurrency_token` varchar(50) NULL,
    `consent_type` varchar(50) NULL,
    `display_name` longtext NULL,
    `display_names` longtext NULL,
    `json_web_key_set` longtext NULL,
    `permissions` longtext NULL,
    `post_logout_redirect_uris` longtext NULL,
    `properties` longtext NULL,
    `redirect_uris` longtext NULL,
    `requirements` longtext NULL,
    `settings` longtext NULL,
    PRIMARY KEY (`id`)
);

CREATE TABLE `dataprotectionkeys` (
    `id` int NOT NULL AUTO_INCREMENT,
    `friendlyname` longtext NULL,
    `xml` longtext NULL,
    PRIMARY KEY (`id`)
);

CREATE TABLE `roles` (
    `id` varchar(255) NOT NULL,
    `name` varchar(256) NULL,
    `normalizedname` varchar(256) NULL,
    `concurrencystamp` longtext NULL,
    PRIMARY KEY (`id`)
);

CREATE TABLE `scopes` (
    `id` varchar(100) NOT NULL,
    `concurrency_token` varchar(50) NULL,
    `description` longtext NULL,
    `descriptions` longtext NULL,
    `display_name` longtext NULL,
    `display_names` longtext NULL,
    `name` varchar(200) NULL,
    `properties` longtext NULL,
    `resources` longtext NULL,
    PRIMARY KEY (`id`)
);

CREATE TABLE `userpasskeys` (
    `credentialid` varbinary(1024) NOT NULL,
    `userid` varchar(255) NOT NULL,
    `publickey` longblob NOT NULL,
    `name` longtext NULL,
    `createdat` datetime(6) NOT NULL,
    `signcount` int unsigned NOT NULL,
    `transports` longtext NOT NULL,
    `isuserverified` tinyint(1) NOT NULL,
    `isbackupeligible` tinyint(1) NOT NULL,
    `isbackedup` tinyint(1) NOT NULL,
    `attestationobject` longblob NOT NULL,
    `clientdatajson` longblob NOT NULL,
    PRIMARY KEY (`credentialid`)
);

CREATE TABLE `users` (
    `id` varchar(255) NOT NULL,
    `timestamp` timestamp NOT NULL DEFAULT (UTC_TIMESTAMP()),
    `username` varchar(256) NULL,
    `normalizedusername` varchar(256) NULL,
    `email` varchar(256) NULL,
    `normalizedemail` varchar(256) NULL,
    `emailconfirmed` tinyint(1) NOT NULL,
    `passwordhash` longtext NULL,
    `securitystamp` longtext NULL,
    `concurrencystamp` longtext NULL,
    `phonenumber` longtext NULL,
    `phonenumberconfirmed` tinyint(1) NOT NULL,
    `twofactorenabled` tinyint(1) NOT NULL,
    `lockoutend` datetime(6) NULL,
    `lockoutenabled` tinyint(1) NOT NULL,
    `accessfailedcount` int NOT NULL,
    PRIMARY KEY (`id`)
);

CREATE TABLE `authorizations` (
    `id` varchar(100) NOT NULL,
    `application_id` varchar(100) NULL,
    `concurrency_token` varchar(50) NULL,
    `creation_date` datetime(6) NULL,
    `properties` longtext NULL,
    `scopes` longtext NULL,
    `status` varchar(50) NULL,
    `subject` varchar(400) NULL,
    `type` varchar(50) NULL,
    PRIMARY KEY (`id`),
    CONSTRAINT `FK_authorizations_applications_application_id` FOREIGN KEY (`application_id`) REFERENCES `applications` (`id`)
);

CREATE TABLE `roleclaims` (
    `id` int NOT NULL AUTO_INCREMENT,
    `roleid` varchar(255) NOT NULL,
    `claimtype` longtext NULL,
    `claimvalue` longtext NULL,
    PRIMARY KEY (`id`),
    CONSTRAINT `FK_roleclaims_roles_roleid` FOREIGN KEY (`roleid`) REFERENCES `roles` (`id`) ON DELETE CASCADE
);

CREATE TABLE `userclaims` (
    `id` int NOT NULL AUTO_INCREMENT,
    `userid` varchar(255) NOT NULL,
    `claimtype` longtext NULL,
    `claimvalue` longtext NULL,
    PRIMARY KEY (`id`),
    CONSTRAINT `FK_userclaims_users_userid` FOREIGN KEY (`userid`) REFERENCES `users` (`id`) ON DELETE CASCADE
);

CREATE TABLE `userlogins` (
    `loginprovider` varchar(255) NOT NULL,
    `providerkey` varchar(255) NOT NULL,
    `providerdisplayname` longtext NULL,
    `userid` varchar(255) NOT NULL,
    PRIMARY KEY (`loginprovider`, `providerkey`),
    CONSTRAINT `FK_userlogins_users_userid` FOREIGN KEY (`userid`) REFERENCES `users` (`id`) ON DELETE CASCADE
);

CREATE TABLE `userroles` (
    `userid` varchar(255) NOT NULL,
    `roleid` varchar(255) NOT NULL,
    PRIMARY KEY (`userid`, `roleid`),
    CONSTRAINT `FK_userroles_roles_roleid` FOREIGN KEY (`roleid`) REFERENCES `roles` (`id`) ON DELETE CASCADE,
    CONSTRAINT `FK_userroles_users_userid` FOREIGN KEY (`userid`) REFERENCES `users` (`id`) ON DELETE CASCADE
);

CREATE TABLE `usertokens` (
    `userid` varchar(255) NOT NULL,
    `loginprovider` varchar(255) NOT NULL,
    `name` varchar(255) NOT NULL,
    `value` longtext NULL,
    PRIMARY KEY (`userid`, `loginprovider`, `name`),
    CONSTRAINT `FK_usertokens_users_userid` FOREIGN KEY (`userid`) REFERENCES `users` (`id`) ON DELETE CASCADE
);

CREATE TABLE `tokens` (
    `id` varchar(100) NOT NULL,
    `application_id` varchar(100) NULL,
    `authorization_id` varchar(100) NULL,
    `concurrency_token` varchar(50) NULL,
    `creation_date` datetime(6) NULL,
    `expiration_date` datetime(6) NULL,
    `payload` longtext NULL,
    `properties` longtext NULL,
    `redemption_date` datetime(6) NULL,
    `reference_id` varchar(100) NULL,
    `status` varchar(50) NULL,
    `subject` varchar(400) NULL,
    `type` varchar(150) NULL,
    PRIMARY KEY (`id`),
    CONSTRAINT `FK_tokens_applications_application_id` FOREIGN KEY (`application_id`) REFERENCES `applications` (`id`),
    CONSTRAINT `FK_tokens_authorizations_authorization_id` FOREIGN KEY (`authorization_id`) REFERENCES `authorizations` (`id`)
);

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
VALUES ('20260724213612_Initial', '10.0.10');

COMMIT;
