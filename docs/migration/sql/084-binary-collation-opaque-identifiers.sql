-- ============================================================================
-- 084-binary-collation-opaque-identifiers.sql
-- Additive coverage for EF migration
-- 20260814202136_UseBinaryCollationForOpaqueIdentifiers.
--
-- MariaDB defaults every utf8mb4 column to utf8mb4_general_ci
-- (case-insensitive), which silently folds case variants of opaque
-- base64url/GUID identifiers together: reference tokens, session ids,
-- CIBA auth_req_ids/consumption ids, SSF stream ids/delivery keys, DPoP
-- replay keys and management draft GUIDs (eval 2026-08-14, finding F-3).
-- Binary collations restore exact-match semantics.
--
-- Notes:
--   * MODIFY COLUMN rebuilds each table's indexes. On large `tokens` tables
--     run this in a maintenance window; the statements are independent per
--     table, so partial application is safe to resume.
--   * Re-running is semantically idempotent (modifying a column to its
--     current collation) but repeats the rebuild — apply once per upgrade.
--   * Fresh installs already contain these collations in
--     001-create-empty-database.sql; the history insert below keeps both
--     provisioning paths in agreement.
-- ============================================================================

START TRANSACTION;

ALTER TABLE `tokens`
    MODIFY COLUMN `reference_id` varchar(100) CHARACTER SET utf8mb4
        COLLATE utf8mb4_bin NULL;

ALTER TABLE `oidcusersessions`
    MODIFY COLUMN `sessionid` varchar(64) CHARACTER SET utf8mb4
        COLLATE utf8mb4_bin NOT NULL;

ALTER TABLE `cibapendingstates`
    MODIFY COLUMN `authreqid` varchar(64) CHARACTER SET utf8mb4
        COLLATE utf8mb4_bin NOT NULL,
    MODIFY COLUMN `consumptionid` varchar(64) CHARACTER SET utf8mb4
        COLLATE utf8mb4_bin NULL;

ALTER TABLE `ssfstreams`
    MODIFY COLUMN `streamid` varchar(64) CHARACTER SET utf8mb4
        COLLATE utf8mb4_bin NOT NULL,
    MODIFY COLUMN `verificationchallengehash` varchar(43) CHARACTER SET utf8mb4
        COLLATE utf8mb4_bin NULL;

ALTER TABLE `ssfsetdeliveries`
    MODIFY COLUMN `streamid` varchar(64) CHARACTER SET utf8mb4
        COLLATE utf8mb4_bin NOT NULL,
    MODIFY COLUMN `deliverykey` varchar(64) CHARACTER SET utf8mb4
        COLLATE utf8mb4_bin NULL;

ALTER TABLE `dpopreplayentries`
    MODIFY COLUMN `key` varchar(64) CHARACTER SET utf8mb4
        COLLATE utf8mb4_bin NOT NULL;

ALTER TABLE `managementclientdrafts`
    MODIFY COLUMN `id` char(36) COLLATE ascii_bin NOT NULL;

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
SELECT '20260814202136_UseBinaryCollationForOpaqueIdentifiers', '10.0.10'
WHERE NOT EXISTS (
    SELECT 1 FROM `__sufficit_identity_migrations`
    WHERE `MigrationId` = '20260814202136_UseBinaryCollationForOpaqueIdentifiers'
);

COMMIT;
