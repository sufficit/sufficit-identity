-- System users: ordinary users to every application that never sign in
-- interactively, plus the one-time enrollment codes an operator issues for
-- them. Additive; apply once, before deploying the corresponding binaries.
START TRANSACTION;
CREATE TABLE `systemusers` (
    `userid` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `createdby` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `createdatutc` datetime(6) NOT NULL,
    `correlationid` varchar(64) CHARACTER SET utf8mb4 NULL,
    `disabledatutc` datetime(6) NULL,
    `disabledby` varchar(255) CHARACTER SET utf8mb4 NULL,
    CONSTRAINT `PK_systemusers` PRIMARY KEY (`userid`),
    CONSTRAINT `FK_systemusers_users_userid` FOREIGN KEY (`userid`) REFERENCES `users` (`id`) ON DELETE CASCADE
) CHARACTER SET=utf8mb4;

CREATE TABLE `systemuserenrollments` (
    `id` char(36) COLLATE ascii_general_ci NOT NULL,
    `userid` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `clientid` varchar(100) CHARACTER SET utf8mb4 NOT NULL,
    `label` varchar(100) CHARACTER SET utf8mb4 NOT NULL,
    `codehash` varchar(64) CHARACTER SET utf8mb4 NOT NULL,
    `codehint` varchar(12) CHARACTER SET utf8mb4 NOT NULL,
    `issuedby` varchar(255) CHARACTER SET utf8mb4 NOT NULL,
    `createdatutc` datetime(6) NOT NULL,
    `expiresatutc` datetime(6) NOT NULL,
    `redeemedatutc` datetime(6) NULL,
    `authorizationid` varchar(100) CHARACTER SET utf8mb4 NULL,
    `revokedatutc` datetime(6) NULL,
    `revokedby` varchar(255) CHARACTER SET utf8mb4 NULL,
    CONSTRAINT `PK_systemuserenrollments` PRIMARY KEY (`id`),
    CONSTRAINT `FK_systemuserenrollments_systemusers_userid` FOREIGN KEY (`userid`) REFERENCES `systemusers` (`userid`) ON DELETE CASCADE
) CHARACTER SET=utf8mb4;

CREATE UNIQUE INDEX `IX_systemuserenrollments_codehash` ON `systemuserenrollments` (`codehash`);

CREATE INDEX `IX_systemuserenrollments_userid` ON `systemuserenrollments` (`userid`);

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
VALUES ('20261021163537_AddSystemUsers', '10.0.13');

COMMIT;

