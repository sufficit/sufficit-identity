-- One-shot reconciliation for the audited 2026-08-04 cutover.
-- Run only after 090-audit-post-cutover-drift.sql and a protected target dump.
-- This script intentionally excludes OAuth grants/tokens and client secrets.

SET @cutover_utc = TIMESTAMP('2026-08-04 02:09:00');
USE identity;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;
START TRANSACTION WITH CONSISTENT SNAPSHOT;

-- A CHECK-backed temporary table turns changed preconditions into a hard SQL
-- error. The MariaDB client then stops and the uncommitted transaction rolls
-- back when the connection closes.
CREATE TEMPORARY TABLE `_identity_reconcile_guard` (
    `valid` tinyint NOT NULL CHECK (`valid` = 1)
);

SET @missing_users = (
    SELECT COUNT(*)
    FROM identity_legacy.users l
    LEFT JOIN identity.users n ON n.id = l.id
    WHERE n.id IS NULL
);
SET @email_conflicts = (
    SELECT COUNT(*)
    FROM identity_legacy.users l
    JOIN identity.users n
      ON n.normalizedemail = l.normalizedemail AND n.id <> l.id
    WHERE l.normalizedemail IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM identity.users same_id WHERE same_id.id = l.id)
);
SET @username_conflicts = (
    SELECT COUNT(*)
    FROM identity_legacy.users l
    JOIN identity.users n
      ON n.normalizedusername = l.normalizedusername AND n.id <> l.id
    WHERE l.normalizedusername IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM identity.users same_id WHERE same_id.id = l.id)
);
SET @missing_claims = (
    SELECT COUNT(*)
    FROM identity_legacy.userclaims l
    WHERE NOT EXISTS (
        SELECT 1 FROM identity.userclaims n
        WHERE n.userid = l.userid
          AND n.claimtype <=> l.claimtype
          AND n.claimvalue <=> l.claimvalue
    )
);
SET @missing_logins = (
    SELECT COUNT(*)
    FROM identity_legacy.userlogins l
    WHERE NOT EXISTS (
        SELECT 1 FROM identity.userlogins n
        WHERE n.loginprovider = l.loginprovider
          AND n.providerkey = l.providerkey
    )
);
SET @safe_password_updates = (
    SELECT COUNT(*)
    FROM identity.users_backup_20260804_020900 b
    JOIN identity_legacy.users l ON l.id = b.id
    JOIN identity.users n ON n.id = b.id
    WHERE NOT (l.passwordhash <=> b.passwordhash)
      AND (n.passwordhash <=> b.passwordhash)
);
SET @unsafe_password_conflicts = (
    SELECT COUNT(*)
    FROM identity.users_backup_20260804_020900 b
    JOIN identity_legacy.users l ON l.id = b.id
    JOIN identity.users n ON n.id = b.id
    WHERE NOT (l.passwordhash <=> b.passwordhash)
      AND NOT (n.passwordhash <=> b.passwordhash)
      AND NOT (n.passwordhash <=> l.passwordhash)
);
SET @safe_security_stamp_updates = (
    SELECT COUNT(*)
    FROM identity.users_backup_20260804_020900 b
    JOIN identity_legacy.users l ON l.id = b.id
    JOIN identity.users n ON n.id = b.id
    WHERE NOT (l.securitystamp <=> b.securitystamp)
      AND (n.securitystamp <=> b.securitystamp)
);
SET @unsafe_security_stamp_conflicts = (
    SELECT COUNT(*)
    FROM identity.users_backup_20260804_020900 b
    JOIN identity_legacy.users l ON l.id = b.id
    JOIN identity.users n ON n.id = b.id
    WHERE NOT (l.securitystamp <=> b.securitystamp)
      AND NOT (n.securitystamp <=> b.securitystamp)
      AND NOT (n.securitystamp <=> l.securitystamp)
);

SELECT @missing_users AS missing_users,
       @email_conflicts AS email_conflicts,
       @username_conflicts AS username_conflicts,
       @missing_claims AS missing_claims,
       @missing_logins AS missing_logins,
       @safe_password_updates AS safe_password_updates,
       @unsafe_password_conflicts AS unsafe_password_conflicts,
       @safe_security_stamp_updates AS safe_security_stamp_updates,
       @unsafe_security_stamp_conflicts AS unsafe_security_stamp_conflicts;

INSERT INTO `_identity_reconcile_guard` (`valid`)
SELECT IF(
    @missing_users = 96
    AND @email_conflicts = 0
    AND @username_conflicts = 0
    AND @missing_claims = 22
    AND @missing_logins = 1
    AND @safe_password_updates = 1
    AND @unsafe_password_conflicts = 0
    AND @safe_security_stamp_updates = 2
    AND @unsafe_security_stamp_conflicts = 0,
    1,
    0
);

INSERT INTO identity.users (
    id, `timestamp`, username, normalizedusername, email, normalizedemail,
    emailconfirmed, passwordhash, securitystamp, concurrencystamp,
    phonenumber, phonenumberconfirmed, twofactorenabled, lockoutend,
    lockoutenabled, accessfailedcount, createdatutc
)
SELECT
    l.id, l.`timestamp`, l.username, l.normalizedusername, l.email,
    l.normalizedemail, l.emailconfirmed, l.passwordhash, l.securitystamp,
    l.concurrencystamp, l.phonenumber, l.phonenumberconfirmed,
    l.twofactorenabled, l.lockoutend, l.lockoutenabled, l.accessfailedcount,
    CAST(l.`timestamp` AS datetime(6))
FROM identity_legacy.users l
WHERE NOT EXISTS (SELECT 1 FROM identity.users n WHERE n.id = l.id)
  AND NOT EXISTS (
      SELECT 1 FROM identity.users n
      WHERE l.normalizedemail IS NOT NULL
        AND n.normalizedemail = l.normalizedemail
        AND n.id <> l.id
  )
  AND NOT EXISTS (
      SELECT 1 FROM identity.users n
      WHERE l.normalizedusername IS NOT NULL
        AND n.normalizedusername = l.normalizedusername
        AND n.id <> l.id
  );
SET @inserted_users = ROW_COUNT();
INSERT INTO `_identity_reconcile_guard` (`valid`)
VALUES (IF(@inserted_users = @missing_users, 1, 0));

INSERT INTO identity.userclaims (userid, claimtype, claimvalue)
SELECT l.userid, l.claimtype, l.claimvalue
FROM identity_legacy.userclaims l
WHERE EXISTS (SELECT 1 FROM identity.users u WHERE u.id = l.userid)
  AND NOT EXISTS (
      SELECT 1 FROM identity.userclaims n
      WHERE n.userid = l.userid
        AND n.claimtype <=> l.claimtype
        AND n.claimvalue <=> l.claimvalue
  );
SET @inserted_claims = ROW_COUNT();
INSERT INTO `_identity_reconcile_guard` (`valid`)
VALUES (IF(@inserted_claims = @missing_claims, 1, 0));

INSERT INTO identity.userlogins (loginprovider, providerkey, providerdisplayname, userid)
SELECT l.loginprovider, l.providerkey, l.providerdisplayname, l.userid
FROM identity_legacy.userlogins l
WHERE EXISTS (SELECT 1 FROM identity.users u WHERE u.id = l.userid)
  AND NOT EXISTS (
      SELECT 1 FROM identity.userlogins n
      WHERE n.loginprovider = l.loginprovider
        AND n.providerkey = l.providerkey
  );
SET @inserted_logins = ROW_COUNT();
INSERT INTO `_identity_reconcile_guard` (`valid`)
VALUES (IF(@inserted_logins = @missing_logins, 1, 0));

UPDATE identity.users n
JOIN identity_legacy.users l ON l.id = n.id
JOIN identity.users_backup_20260804_020900 b ON b.id = n.id
SET n.passwordhash = l.passwordhash
WHERE NOT (l.passwordhash <=> b.passwordhash)
  AND (n.passwordhash <=> b.passwordhash);
SET @updated_passwords = ROW_COUNT();
INSERT INTO `_identity_reconcile_guard` (`valid`)
VALUES (IF(@updated_passwords = @safe_password_updates, 1, 0));

UPDATE identity.users n
JOIN identity_legacy.users l ON l.id = n.id
JOIN identity.users_backup_20260804_020900 b ON b.id = n.id
SET n.securitystamp = l.securitystamp,
    n.concurrencystamp = UUID()
WHERE NOT (l.securitystamp <=> b.securitystamp)
  AND (n.securitystamp <=> b.securitystamp);
SET @updated_security_stamps = ROW_COUNT();
INSERT INTO `_identity_reconcile_guard` (`valid`)
VALUES (IF(@updated_security_stamps = @safe_security_stamp_updates, 1, 0));

SET @reconciliation_id = CONCAT('legacy-reconcile-', DATE_FORMAT(UTC_TIMESTAMP(6), '%Y%m%dT%H%i%s%fZ'));
INSERT INTO identity.managementauditevents (
    occurredatutc, operatorsubject, operatordisplayname, capability,
    resourcetype, resourceid, contextid, authorizationoutcome,
    operationoutcome, reasoncode, correlationid, authenticationmethods
)
VALUES (
    UTC_TIMESTAMP(6), 'system:legacy-reconciliation',
    'Sufficit Identity migration operator', 'identity.migration.reconcile',
    'identity-database', 'identity_legacy', NULL, 'authorized', 'succeeded',
    'post_cutover_drift', @reconciliation_id, 'ssh,backup,consistent-snapshot'
);

COMMIT;

SELECT @reconciliation_id AS reconciliation_id,
       @inserted_users AS inserted_users,
       @inserted_claims AS inserted_claims,
       @inserted_logins AS inserted_logins,
       @updated_passwords AS updated_passwords,
       @updated_security_stamps AS updated_security_stamps;
