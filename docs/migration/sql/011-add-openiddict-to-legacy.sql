-- Additive schema preparation for an isolated, preflighted Skoruba/Duende
-- database clone. This script does not copy or alter shared Identity data.
--
-- MySQL/MariaDB DDL performs implicit commits. Backup and rehearsal are
-- mandatory; START TRANSACTION would not make these statements atomic.

CREATE TABLE `__sufficit_identity_migrations` (
    `MigrationId` varchar(150) NOT NULL,
    `ProductVersion` varchar(32) NOT NULL,
    PRIMARY KEY (`MigrationId`)
);

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

CREATE UNIQUE INDEX `AK_OpenIddictApplications_ClientId`
    ON `applications` (`client_id`);

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

CREATE UNIQUE INDEX `AK_OpenIddictScopes_Name`
    ON `scopes` (`name`);

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
    CONSTRAINT `FK_authorizations_applications_application_id`
        FOREIGN KEY (`application_id`) REFERENCES `applications` (`id`)
);

CREATE INDEX
    `IX_OpenIddictAuthorizations_ApplicationId_Status_Subject_Type`
    ON `authorizations` (`application_id`, `status`, `subject`, `type`);

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
    CONSTRAINT `FK_tokens_applications_application_id`
        FOREIGN KEY (`application_id`) REFERENCES `applications` (`id`),
    CONSTRAINT `FK_tokens_authorizations_authorization_id`
        FOREIGN KEY (`authorization_id`) REFERENCES `authorizations` (`id`)
);

CREATE UNIQUE INDEX `AK_OpenIddictTokens_ReferenceId`
    ON `tokens` (`reference_id`);

CREATE INDEX `IX_OpenIddictTokens_ApplicationId_Status_Subject_Type`
    ON `tokens` (`application_id`, `status`, `subject`, `type`);

CREATE INDEX `IX_OpenIddictTokens_AuthorizationId`
    ON `tokens` (`authorization_id`);

INSERT INTO `__sufficit_identity_migrations`
    (`MigrationId`, `ProductVersion`)
VALUES
    ('20260726213918_Initial', '10.0.10');
