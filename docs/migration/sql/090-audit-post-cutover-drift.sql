-- Read-only post-cutover drift audit.
--
-- Production layout after the cutover:
--   identity        = current OpenIddict database
--   identity_legacy = retained Duende/Skoruba database
--
-- The users_backup_20260804_020900 table is the immutable user snapshot taken
-- at the cutover. No statement in this file changes data or acquires write
-- locks intentionally.

SET @cutover_utc = TIMESTAMP('2026-08-04 02:09:00');
SET TRANSACTION READ ONLY;
START TRANSACTION WITH CONSISTENT SNAPSHOT;

SELECT 'audit_as_of_utc' AS metric, UTC_TIMESTAMP(6) AS value;
SELECT 'cutover_utc' AS metric, @cutover_utc AS value;

-- Users: source snapshot, retained legacy and current destination.
SELECT 'users_snapshot' AS metric, COUNT(*) AS value
FROM identity.users_backup_20260804_020900
UNION ALL
SELECT 'users_legacy_current', COUNT(*) FROM identity_legacy.users
UNION ALL
SELECT 'users_current', COUNT(*) FROM identity.users
UNION ALL
SELECT 'users_created_in_legacy_after_cutover', COUNT(*)
FROM identity_legacy.users WHERE `timestamp` > @cutover_utc
UNION ALL
SELECT 'users_created_in_current_after_cutover', COUNT(*)
FROM identity.users WHERE createdatutc > @cutover_utc
UNION ALL
SELECT 'users_only_in_legacy_vs_snapshot', COUNT(*)
FROM identity_legacy.users l
LEFT JOIN identity.users_backup_20260804_020900 b ON b.id = l.id
WHERE b.id IS NULL
UNION ALL
SELECT 'users_removed_from_legacy_vs_snapshot', COUNT(*)
FROM identity.users_backup_20260804_020900 b
LEFT JOIN identity_legacy.users l ON l.id = b.id
WHERE l.id IS NULL
UNION ALL
SELECT 'users_only_in_legacy_vs_current', COUNT(*)
FROM identity_legacy.users l
LEFT JOIN identity.users n ON n.id = l.id
WHERE n.id IS NULL
UNION ALL
SELECT 'users_only_in_current_vs_legacy', COUNT(*)
FROM identity.users n
LEFT JOIN identity_legacy.users l ON l.id = n.id
WHERE l.id IS NULL;

-- Changes made in the retained legacy database after the cutover snapshot.
SELECT 'legacy_user_any_semantic_change' AS metric, COUNT(*) AS value
FROM identity_legacy.users l
JOIN identity.users_backup_20260804_020900 b ON b.id = l.id
WHERE NOT (l.username <=> b.username)
   OR NOT (l.normalizedusername <=> b.normalizedusername)
   OR NOT (l.email <=> b.email)
   OR NOT (l.normalizedemail <=> b.normalizedemail)
   OR NOT (l.emailconfirmed <=> b.emailconfirmed)
   OR NOT (l.passwordhash <=> b.passwordhash)
   OR NOT (l.securitystamp <=> b.securitystamp)
   OR NOT (l.concurrencystamp <=> b.concurrencystamp)
   OR NOT (l.phonenumber <=> b.phonenumber)
   OR NOT (l.phonenumberconfirmed <=> b.phonenumberconfirmed)
   OR NOT (l.twofactorenabled <=> b.twofactorenabled)
   OR NOT (l.lockoutend <=> b.lockoutend)
   OR NOT (l.lockoutenabled <=> b.lockoutenabled)
   OR NOT (l.accessfailedcount <=> b.accessfailedcount)
UNION ALL
SELECT 'legacy_user_password_changed', COUNT(*)
FROM identity_legacy.users l
JOIN identity.users_backup_20260804_020900 b ON b.id = l.id
WHERE NOT (l.passwordhash <=> b.passwordhash)
UNION ALL
SELECT 'legacy_user_security_stamp_changed', COUNT(*)
FROM identity_legacy.users l
JOIN identity.users_backup_20260804_020900 b ON b.id = l.id
WHERE NOT (l.securitystamp <=> b.securitystamp)
UNION ALL
SELECT 'legacy_user_email_or_confirmation_changed', COUNT(*)
FROM identity_legacy.users l
JOIN identity.users_backup_20260804_020900 b ON b.id = l.id
WHERE NOT (l.email <=> b.email)
   OR NOT (l.normalizedemail <=> b.normalizedemail)
   OR NOT (l.emailconfirmed <=> b.emailconfirmed)
UNION ALL
SELECT 'legacy_user_phone_or_confirmation_changed', COUNT(*)
FROM identity_legacy.users l
JOIN identity.users_backup_20260804_020900 b ON b.id = l.id
WHERE NOT (l.phonenumber <=> b.phonenumber)
   OR NOT (l.phonenumberconfirmed <=> b.phonenumberconfirmed)
UNION ALL
SELECT 'legacy_user_mfa_changed', COUNT(*)
FROM identity_legacy.users l
JOIN identity.users_backup_20260804_020900 b ON b.id = l.id
WHERE NOT (l.twofactorenabled <=> b.twofactorenabled)
UNION ALL
SELECT 'legacy_user_lockout_or_failures_changed', COUNT(*)
FROM identity_legacy.users l
JOIN identity.users_backup_20260804_020900 b ON b.id = l.id
WHERE NOT (l.lockoutend <=> b.lockoutend)
   OR NOT (l.lockoutenabled <=> b.lockoutenabled)
   OR NOT (l.accessfailedcount <=> b.accessfailedcount);

-- Direct destination comparison. Password/security-stamp divergence is kept
-- separate because blindly choosing either side can invalidate credentials.
SELECT 'shared_users_with_any_semantic_divergence' AS metric, COUNT(*) AS value
FROM identity_legacy.users l
JOIN identity.users n ON n.id = l.id
WHERE NOT (l.username <=> n.username)
   OR NOT (l.normalizedusername <=> n.normalizedusername)
   OR NOT (l.email <=> n.email)
   OR NOT (l.normalizedemail <=> n.normalizedemail)
   OR NOT (l.emailconfirmed <=> n.emailconfirmed)
   OR NOT (l.passwordhash <=> n.passwordhash)
   OR NOT (l.securitystamp <=> n.securitystamp)
   OR NOT (l.concurrencystamp <=> n.concurrencystamp)
   OR NOT (l.phonenumber <=> n.phonenumber)
   OR NOT (l.phonenumberconfirmed <=> n.phonenumberconfirmed)
   OR NOT (l.twofactorenabled <=> n.twofactorenabled)
   OR NOT (l.lockoutend <=> n.lockoutend)
   OR NOT (l.lockoutenabled <=> n.lockoutenabled)
   OR NOT (l.accessfailedcount <=> n.accessfailedcount)
UNION ALL
SELECT 'shared_users_password_divergence', COUNT(*)
FROM identity_legacy.users l JOIN identity.users n ON n.id = l.id
WHERE NOT (l.passwordhash <=> n.passwordhash)
UNION ALL
SELECT 'shared_users_security_stamp_divergence', COUNT(*)
FROM identity_legacy.users l JOIN identity.users n ON n.id = l.id
WHERE NOT (l.securitystamp <=> n.securitystamp);

-- ASP.NET Identity child tables.
SELECT 'claims_only_in_legacy_by_id' AS metric, COUNT(*) AS value
FROM identity_legacy.userclaims l
LEFT JOIN identity.userclaims n ON n.id = l.id
WHERE n.id IS NULL
UNION ALL
SELECT 'claims_only_in_current_by_id', COUNT(*)
FROM identity.userclaims n
LEFT JOIN identity_legacy.userclaims l ON l.id = n.id
WHERE l.id IS NULL
UNION ALL
SELECT 'claims_shared_id_with_different_value', COUNT(*)
FROM identity_legacy.userclaims l
JOIN identity.userclaims n ON n.id = l.id
WHERE NOT (l.userid <=> n.userid)
   OR NOT (l.claimtype <=> n.claimtype)
   OR NOT (l.claimvalue <=> n.claimvalue)
UNION ALL
SELECT 'logins_only_in_legacy', COUNT(*)
FROM identity_legacy.userlogins l
LEFT JOIN identity.userlogins n
  ON n.loginprovider = l.loginprovider AND n.providerkey = l.providerkey
WHERE n.providerkey IS NULL
UNION ALL
SELECT 'logins_only_in_current', COUNT(*)
FROM identity.userlogins n
LEFT JOIN identity_legacy.userlogins l
  ON l.loginprovider = n.loginprovider AND l.providerkey = n.providerkey
WHERE l.providerkey IS NULL
UNION ALL
SELECT 'roles_only_in_legacy', COUNT(*)
FROM identity_legacy.userroles l
LEFT JOIN identity.userroles n ON n.userid = l.userid AND n.roleid = l.roleid
WHERE n.userid IS NULL
UNION ALL
SELECT 'roles_only_in_current', COUNT(*)
FROM identity.userroles n
LEFT JOIN identity_legacy.userroles l ON l.userid = n.userid AND l.roleid = n.roleid
WHERE l.userid IS NULL
UNION ALL
SELECT 'user_tokens_only_in_legacy', COUNT(*)
FROM identity_legacy.usertokens l
LEFT JOIN identity.usertokens n
  ON n.userid = l.userid
 AND n.loginprovider = l.loginprovider
 AND n.name = l.name
WHERE n.userid IS NULL
UNION ALL
SELECT 'user_tokens_only_in_current', COUNT(*)
FROM identity.usertokens n
LEFT JOIN identity_legacy.usertokens l
  ON l.userid = n.userid
 AND l.loginprovider = n.loginprovider
 AND l.name = n.name
WHERE l.userid IS NULL
UNION ALL
SELECT 'user_tokens_shared_key_with_different_value', COUNT(*)
FROM identity_legacy.usertokens l
JOIN identity.usertokens n
  ON n.userid = l.userid
 AND n.loginprovider = l.loginprovider
 AND n.name = l.name
WHERE NOT (n.value <=> l.value);

SELECT 'claims_missing_semantically_legacy_to_current' AS metric, COUNT(*) AS value
FROM identity_legacy.userclaims l
WHERE NOT EXISTS (
    SELECT 1 FROM identity.userclaims n
    WHERE n.userid = l.userid
      AND n.claimtype <=> l.claimtype
      AND n.claimvalue <=> l.claimvalue
)
UNION ALL
SELECT 'current_claims_with_missing_user', COUNT(*)
FROM identity.userclaims c
LEFT JOIN identity.users u ON u.id = c.userid
WHERE u.id IS NULL
UNION ALL
SELECT 'current_logins_with_missing_user', COUNT(*)
FROM identity.userlogins l
LEFT JOIN identity.users u ON u.id = l.userid
WHERE u.id IS NULL;

-- Client registrations. A semantic field-by-field conversion must use the
-- migration mapper; these metrics identify candidates that require it.
SELECT 'applications_only_in_legacy' AS metric, COUNT(*) AS value
FROM identity_legacy.clients l
LEFT JOIN identity.applications n ON n.client_id = l.clientid
WHERE n.client_id IS NULL
UNION ALL
SELECT 'applications_only_in_current', COUNT(*)
FROM identity.applications n
LEFT JOIN identity_legacy.clients l ON l.clientid = n.client_id
WHERE l.clientid IS NULL
UNION ALL
SELECT 'legacy_applications_created_after_cutover', COUNT(*)
FROM identity_legacy.clients WHERE created > @cutover_utc
UNION ALL
SELECT 'legacy_applications_updated_after_cutover', COUNT(*)
FROM identity_legacy.clients WHERE updated > @cutover_utc;

-- RFC/OIDC runtime artifacts are not portable across issuers. Only legacy
-- reference-token identifiers are expected in the new database, as revoked
-- metadata tombstones; payloads and usable token values must not be copied.
SELECT 'legacy_grants_created_after_cutover' AS metric, COUNT(*) AS value
FROM identity_legacy.persistedgrants
WHERE creationtime > @cutover_utc
UNION ALL
SELECT 'legacy_active_grants_created_after_cutover', COUNT(*)
FROM identity_legacy.persistedgrants
WHERE creationtime > @cutover_utc
  AND consumedtime IS NULL
  AND (expiration IS NULL OR expiration > UTC_TIMESTAMP(6))
UNION ALL
SELECT 'legacy_reference_tokens_total', COUNT(*)
FROM identity_legacy.persistedgrants
WHERE type = 'reference_token' AND `key` IS NOT NULL AND CHAR_LENGTH(`key`) <= 100
UNION ALL
SELECT 'legacy_reference_token_tombstones_missing', COUNT(*)
FROM identity_legacy.persistedgrants l
LEFT JOIN identity.tokens n
  ON n.id = CONCAT('legacy-', l.id) OR n.reference_id = l.`key`
WHERE l.type = 'reference_token'
  AND l.`key` IS NOT NULL
  AND CHAR_LENGTH(l.`key`) <= 100
  AND n.id IS NULL
UNION ALL
SELECT 'current_legacy_reference_token_tombstones', COUNT(*)
FROM identity.tokens WHERE type = 'legacy_reference_token';

SELECT type AS legacy_grant_type,
       COUNT(*) AS created_after_cutover,
       SUM(consumedtime IS NULL AND (expiration IS NULL OR expiration > UTC_TIMESTAMP(6))) AS still_active
FROM identity_legacy.persistedgrants
WHERE creationtime > @cutover_utc
GROUP BY type
ORDER BY type;

-- Importability of users that exist only in the retained legacy database.
SELECT 'legacy_only_users_created_after_cutover' AS metric, COUNT(*) AS value
FROM identity_legacy.users l
LEFT JOIN identity.users n ON n.id = l.id
WHERE n.id IS NULL AND l.`timestamp` > @cutover_utc
UNION ALL
SELECT 'legacy_only_users_with_older_timestamp', COUNT(*)
FROM identity_legacy.users l
LEFT JOIN identity.users n ON n.id = l.id
WHERE n.id IS NULL AND l.`timestamp` <= @cutover_utc
UNION ALL
SELECT 'legacy_only_users_email_conflict_in_current', COUNT(*)
FROM identity_legacy.users l
JOIN identity.users n
  ON n.normalizedemail = l.normalizedemail AND n.id <> l.id
WHERE l.normalizedemail IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM identity.users same_id WHERE same_id.id = l.id)
UNION ALL
SELECT 'legacy_only_users_username_conflict_in_current', COUNT(*)
FROM identity_legacy.users l
JOIN identity.users n
  ON n.normalizedusername = l.normalizedusername AND n.id <> l.id
WHERE l.normalizedusername IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM identity.users same_id WHERE same_id.id = l.id)
UNION ALL
SELECT 'legacy_claims_for_legacy_only_users', COUNT(*)
FROM identity_legacy.userclaims c
JOIN identity_legacy.users l ON l.id = c.userid
LEFT JOIN identity.users n ON n.id = l.id
WHERE n.id IS NULL
UNION ALL
SELECT 'legacy_logins_for_legacy_only_users', COUNT(*)
FROM identity_legacy.userlogins c
JOIN identity_legacy.users l ON l.id = c.userid
LEFT JOIN identity.users n ON n.id = l.id
WHERE n.id IS NULL
UNION ALL
SELECT 'legacy_roles_for_legacy_only_users', COUNT(*)
FROM identity_legacy.userroles c
JOIN identity_legacy.users l ON l.id = c.userid
LEFT JOIN identity.users n ON n.id = l.id
WHERE n.id IS NULL
UNION ALL
SELECT 'legacy_user_tokens_for_legacy_only_users', COUNT(*)
FROM identity_legacy.usertokens c
JOIN identity_legacy.users l ON l.id = c.userid
LEFT JOIN identity.users n ON n.id = l.id
WHERE n.id IS NULL;

-- Three-way credential conflict classification against the cutover snapshot.
SELECT 'password_changed_legacy_only' AS metric, COUNT(*) AS value
FROM identity.users_backup_20260804_020900 b
JOIN identity_legacy.users l ON l.id = b.id
JOIN identity.users n ON n.id = b.id
WHERE NOT (l.passwordhash <=> b.passwordhash)
  AND (n.passwordhash <=> b.passwordhash)
UNION ALL
SELECT 'password_changed_current_only', COUNT(*)
FROM identity.users_backup_20260804_020900 b
JOIN identity_legacy.users l ON l.id = b.id
JOIN identity.users n ON n.id = b.id
WHERE (l.passwordhash <=> b.passwordhash)
  AND NOT (n.passwordhash <=> b.passwordhash)
UNION ALL
SELECT 'password_changed_both_same_value', COUNT(*)
FROM identity.users_backup_20260804_020900 b
JOIN identity_legacy.users l ON l.id = b.id
JOIN identity.users n ON n.id = b.id
WHERE NOT (l.passwordhash <=> b.passwordhash)
  AND NOT (n.passwordhash <=> b.passwordhash)
  AND (l.passwordhash <=> n.passwordhash)
UNION ALL
SELECT 'password_changed_both_conflict', COUNT(*)
FROM identity.users_backup_20260804_020900 b
JOIN identity_legacy.users l ON l.id = b.id
JOIN identity.users n ON n.id = b.id
WHERE NOT (l.passwordhash <=> b.passwordhash)
  AND NOT (n.passwordhash <=> b.passwordhash)
  AND NOT (l.passwordhash <=> n.passwordhash);

-- Identifiers are operational configuration, not secrets. This list explains
-- why a client is absent without exposing its secret material.
SELECT l.clientid AS legacy_only_client_id,
       l.enabled,
       l.requireclientsecret,
       l.created,
       l.updated,
       COALESCE(l.description LIKE '%OBSOLETE%', 0) AS marked_obsolete,
       COALESCE(l.description LIKE '%DEPRECATED%' OR l.description LIKE '%deprec%', 0) AS marked_deprecated
FROM identity_legacy.clients l
LEFT JOIN identity.applications n ON n.client_id = l.clientid
WHERE n.client_id IS NULL
ORDER BY l.clientid;

SELECT n.client_id AS current_only_client_id, n.client_type, n.display_name
FROM identity.applications n
LEFT JOIN identity_legacy.clients l ON l.clientid = n.client_id
WHERE l.clientid IS NULL
ORDER BY n.client_id;

SELECT 'legacy_username_changed' AS metric, COUNT(*) AS value
FROM identity_legacy.users l
JOIN identity.users_backup_20260804_020900 b ON b.id = l.id
WHERE NOT (l.username <=> b.username)
   OR NOT (l.normalizedusername <=> b.normalizedusername)
UNION ALL
SELECT 'legacy_concurrency_stamp_changed', COUNT(*)
FROM identity_legacy.users l
JOIN identity.users_backup_20260804_020900 b ON b.id = l.id
WHERE NOT (l.concurrencystamp <=> b.concurrencystamp)
UNION ALL
SELECT 'legacy_access_failed_count_changed', COUNT(*)
FROM identity_legacy.users l
JOIN identity.users_backup_20260804_020900 b ON b.id = l.id
WHERE NOT (l.accessfailedcount <=> b.accessfailedcount)
UNION ALL
SELECT 'legacy_lockout_end_changed', COUNT(*)
FROM identity_legacy.users l
JOIN identity.users_backup_20260804_020900 b ON b.id = l.id
WHERE NOT (l.lockoutend <=> b.lockoutend);

SELECT l.claimtype AS legacy_missing_claim_type, COUNT(*) AS value
FROM identity_legacy.userclaims l
WHERE NOT EXISTS (
    SELECT 1
    FROM identity.userclaims n
    WHERE n.userid = l.userid
      AND n.claimtype <=> l.claimtype
      AND n.claimvalue <=> l.claimvalue
)
GROUP BY l.claimtype
ORDER BY l.claimtype;

SELECT n.claimtype AS current_extra_claim_type, COUNT(*) AS value
FROM identity.userclaims n
WHERE NOT EXISTS (
    SELECT 1
    FROM identity_legacy.userclaims l
    WHERE l.userid = n.userid
      AND l.claimtype <=> n.claimtype
      AND l.claimvalue <=> n.claimvalue
)
GROUP BY n.claimtype
ORDER BY n.claimtype;

SELECT l.clientid AS legacy_client_created_after_cutover,
       l.enabled,
       l.requireclientsecret,
       l.created,
       EXISTS (
           SELECT 1 FROM identity.applications n WHERE n.client_id = l.clientid
       ) AS already_in_current
FROM identity_legacy.clients l
WHERE l.created > @cutover_utc
ORDER BY l.created, l.clientid;

SELECT CASE WHEN n.id IS NULL THEN 'legacy_only_user' ELSE 'shared_user' END AS user_presence,
       l.claimtype,
       COUNT(*) AS missing_claims
FROM identity_legacy.userclaims l
LEFT JOIN identity.users n ON n.id = l.userid
WHERE NOT EXISTS (
    SELECT 1
    FROM identity.userclaims current_claim
    WHERE current_claim.userid = l.userid
      AND current_claim.claimtype <=> l.claimtype
      AND current_claim.claimvalue <=> l.claimvalue
)
GROUP BY user_presence, l.claimtype
ORDER BY user_presence, l.claimtype;

SELECT CASE WHEN n.id IS NULL THEN 'legacy_only_user' ELSE 'shared_user' END AS user_presence,
       COUNT(*) AS missing_logins
FROM identity_legacy.userlogins l
LEFT JOIN identity.users n ON n.id = l.userid
WHERE NOT EXISTS (
    SELECT 1
    FROM identity.userlogins current_login
    WHERE current_login.loginprovider = l.loginprovider
      AND current_login.providerkey = l.providerkey
)
GROUP BY user_presence
ORDER BY user_presence;

SELECT SHA2(l.userid, 256) AS user_key_sha256,
       EXISTS (SELECT 1 FROM identity.users n WHERE n.id = l.userid) AS user_exists_current,
       EXISTS (SELECT 1 FROM identity.roles r WHERE r.id = l.roleid) AS role_exists_current
FROM identity_legacy.userroles l
WHERE NOT EXISTS (
    SELECT 1 FROM identity.userroles n
    WHERE n.userid = l.userid AND n.roleid = l.roleid
);

SELECT SHA2(l.id, 256) AS user_key_sha256,
       l.`timestamp` AS legacy_created_or_recorded_utc,
       NOT (l.passwordhash <=> b.passwordhash) AS password_changed_legacy,
       NOT (l.securitystamp <=> b.securitystamp) AS security_stamp_changed_legacy,
       NOT (l.concurrencystamp <=> b.concurrencystamp) AS concurrency_stamp_changed_legacy,
       NOT (n.passwordhash <=> b.passwordhash) AS password_changed_current,
       NOT (n.securitystamp <=> b.securitystamp) AS security_stamp_changed_current
FROM identity_legacy.users l
JOIN identity.users_backup_20260804_020900 b ON b.id = l.id
JOIN identity.users n ON n.id = l.id
WHERE NOT (l.passwordhash <=> b.passwordhash)
   OR NOT (l.securitystamp <=> b.securitystamp)
ORDER BY user_key_sha256;

SELECT 'data_protection_keys_only_in_legacy' AS metric, COUNT(*) AS value
FROM identity_legacy.dataprotectionkeys l
WHERE NOT EXISTS (
    SELECT 1 FROM identity.dataprotectionkeys n
    WHERE n.friendlyname <=> l.friendlyname AND n.xml <=> l.xml
)
UNION ALL
SELECT 'data_protection_keys_only_in_current', COUNT(*)
FROM identity.dataprotectionkeys n
WHERE NOT EXISTS (
    SELECT 1 FROM identity_legacy.dataprotectionkeys l
    WHERE l.friendlyname <=> n.friendlyname AND l.xml <=> n.xml
)
UNION ALL
SELECT 'enabled_scopes_only_in_legacy', COUNT(*)
FROM identity_legacy.apiscopes l
WHERE l.enabled = 1
  AND NOT EXISTS (SELECT 1 FROM identity.scopes n WHERE n.name = l.name)
UNION ALL
SELECT 'passkeys_only_in_legacy', COUNT(*)
FROM identity_legacy.userpasskeys l
WHERE NOT EXISTS (
    SELECT 1 FROM identity.userpasskeys n WHERE n.credentialid = l.credentialid
);

SELECT l.clientid AS legacy_client_id,
       (SELECT COUNT(*) FROM identity_legacy.clientredirecturis x WHERE x.clientid = l.id) AS redirect_uris,
       (SELECT COUNT(*) FROM identity_legacy.clientpostlogoutredirecturis x WHERE x.clientid = l.id) AS post_logout_redirect_uris,
       (SELECT COUNT(*) FROM identity_legacy.clientgranttypes x WHERE x.clientid = l.id) AS grant_types,
       (SELECT COUNT(*) FROM identity_legacy.clientscopes x WHERE x.clientid = l.id) AS scopes,
       (SELECT COUNT(*) FROM identity_legacy.clientcorsorigins x WHERE x.clientid = l.id) AS cors_origins,
       (SELECT COUNT(*) FROM identity_legacy.clientsecrets x WHERE x.clientid = l.id) AS stored_secret_hashes
FROM identity_legacy.clients l
LEFT JOIN identity.applications n ON n.client_id = l.clientid
WHERE n.client_id IS NULL
  AND l.enabled = 1
  AND COALESCE(l.description, '') NOT LIKE '%OBSOLETE%'
  AND COALESCE(l.description, '') NOT LIKE '%DEPRECATED%'
  AND COALESCE(l.description, '') NOT LIKE '%deprec%'
ORDER BY l.clientid;

COMMIT;
