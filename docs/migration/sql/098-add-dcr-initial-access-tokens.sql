-- Per-registrant initial access tokens for dynamic client registration.
-- Apply once, before deploying the corresponding application binaries.
-- The shared static token (identity/dcr/initial-access-token) is retired:
-- remove it from the deployment, or startup fails.
START TRANSACTION;
CREATE TABLE `dcrinitialaccesstokens` (
    `id` char(36) COLLATE ascii_general_ci NOT NULL,
    `label` varchar(100) CHARACTER SET utf8mb4 NOT NULL,
    `tokenhash` varchar(64) CHARACTER SET utf8mb4 NOT NULL,
    `tokenhint` varchar(12) CHARACTER SET utf8mb4 NOT NULL,
    `issuedby` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `createdatutc` datetime(6) NOT NULL,
    `expiresatutc` datetime(6) NOT NULL,
    `singleuse` tinyint(1) NOT NULL,
    `registrationcount` int NOT NULL,
    `lastusedatutc` datetime(6) NULL,
    `revokedatutc` datetime(6) NULL,
    `revokedby` varchar(255) CHARACTER SET utf8mb4 NULL,
    CONSTRAINT `PK_dcrinitialaccesstokens` PRIMARY KEY (`id`)
) CHARACTER SET=utf8mb4;

CREATE INDEX `IX_dcrinitialaccesstokens_expiresatutc` ON `dcrinitialaccesstokens` (`expiresatutc`);

CREATE UNIQUE INDEX `IX_dcrinitialaccesstokens_tokenhash` ON `dcrinitialaccesstokens` (`tokenhash`);

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
VALUES ('20260914012253_AddDcrInitialAccessTokens', '10.0.11');

COMMIT;

