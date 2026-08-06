-- ============================================================================
-- 080-add-oidc-user-sessions.sql
-- Adds the server-side OIDC browser-session store (oidcusersessions), which
-- backs the ITicketStore wired to the ASP.NET Core Identity application cookie
-- (CookieAuthenticationOptions.SessionStore). One row per active SSO session,
-- keyed by the OIDC `sid`. Repeated execution is safe on MariaDB 10.4.
-- Apply AFTER 001-create-empty-database.sql only on databases that pre-date
-- this migration; a fresh database already includes this table.
-- ============================================================================

CREATE TABLE IF NOT EXISTS `oidcusersessions` (
    `id`              BIGINT       NOT NULL AUTO_INCREMENT,
    `sessionid`       VARCHAR(64)  CHARACTER SET utf8mb4 NOT NULL,
    `subject`         VARCHAR(400) CHARACTER SET utf8mb4 NOT NULL,
    `remoteipaddress` VARCHAR(64)  CHARACTER SET utf8mb4 NULL,
    `useragent`       VARCHAR(512) CHARACTER SET utf8mb4 NULL,
    `createdatutc`    DATETIME(6)  NOT NULL,
    `lastactivityutc` DATETIME(6)  NOT NULL,
    `expiresutc`      DATETIME(6)  NULL,
    `protectedticket` LONGBLOB     NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `AK_oidcusersessions_sessionid` (`sessionid`),
    KEY `IX_oidcusersessions_subject` (`subject`),
    KEY `IX_oidcusersessions_expiresutc` (`expiresutc`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
SELECT '20260806131249_AddOidcUserSessions', '10.0.10'
WHERE NOT EXISTS (
    SELECT 1 FROM `__sufficit_identity_migrations`
    WHERE `MigrationId` = '20260806131249_AddOidcUserSessions'
);
