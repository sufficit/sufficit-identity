-- 094-add-protocol-state-entries.sql
--
-- Durable primary for the protocol state that previously lived only in
-- IDistributedCache: DPoP nonce challenges (RFC 9449 section 8), front-channel
-- logout context, and passkey ceremony tickets.
--
-- Why: IDistributedCache defaults to AddDistributedMemoryCache, which is
-- process-local. With more than one replica that silently degraded three
-- flows — the DPoP nonce dance never converged, a logout fan-out was lost when
-- the browser's follow-up hit another host, and a passkey ceremony started on
-- one replica could not be completed on another. CIBA and the DPoP replay
-- cache already had a database primary; this closes the remaining gap
-- (evaluation 2026-08-30, finding F-4).
--
-- Corresponds to EF migration 20260830224108_AddProtocolStateEntries.
-- Idempotent: safe to re-run.
--
-- `key` is SHA-256(purpose + separator + caller key) in lowercase hex, so it is
-- always exactly 64 characters and never contains the raw nonce partition or
-- ceremony identifier. utf8mb4_bin keeps the lookup case-sensitive, matching
-- every other opaque identifier (see 084-binary-collation-opaque-identifiers).
--
-- `payload` is LONGBLOB because the callers store different things: a
-- data-protected passkey ticket (bytes), and vault-encrypted or JSON text
-- (UTF-8 bytes). Values are already encrypted or data-protected by the caller,
-- so the table never holds readable nonce or ticket material.

CREATE TABLE IF NOT EXISTS `protocolstateentries` (
    `key` VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `purpose` VARCHAR(64) CHARACTER SET utf8mb4 NOT NULL,
    `payload` LONGBLOB NOT NULL,
    `expiresatutc` DATETIME(6) NOT NULL,
    PRIMARY KEY (`key`),
    KEY `IX_protocolstateentries_expiresatutc` (`expiresatutc`),
    KEY `IX_protocolstateentries_purpose` (`purpose`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Expired rows are swept opportunistically by the application (roughly once
-- every 256 writes). This statement is only needed when adopting the table on a
-- database that already accumulated rows from an earlier run.
-- DELETE FROM `protocolstateentries` WHERE `expiresatutc` <= UTC_TIMESTAMP(6);
