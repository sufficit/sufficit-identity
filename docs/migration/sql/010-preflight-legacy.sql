-- Read-only preflight for an isolated clone of the Skoruba/Duende database.
-- Success means this query returns ZERO rows.
-- Do not continue when any issue is returned.

SELECT 'missing_shared_table' AS issue, expected.table_name AS object_name
FROM (
    SELECT 'users' AS table_name
    UNION ALL SELECT 'roles'
    UNION ALL SELECT 'roleclaims'
    UNION ALL SELECT 'userclaims'
    UNION ALL SELECT 'userlogins'
    UNION ALL SELECT 'userroles'
    UNION ALL SELECT 'usertokens'
    UNION ALL SELECT 'userpasskeys'
    UNION ALL SELECT 'dataprotectionkeys'
) AS expected
LEFT JOIN information_schema.tables AS actual
    ON actual.table_schema = DATABASE()
   AND actual.table_name = expected.table_name
WHERE actual.table_name IS NULL

UNION ALL

SELECT 'unexpected_shared_column_count', expected.table_name
FROM (
    SELECT 'users' AS table_name, 16 AS expected_count
    UNION ALL SELECT 'roles', 4
    UNION ALL SELECT 'roleclaims', 4
    UNION ALL SELECT 'userclaims', 4
    UNION ALL SELECT 'userlogins', 4
    UNION ALL SELECT 'userroles', 2
    UNION ALL SELECT 'usertokens', 4
    UNION ALL SELECT 'userpasskeys', 12
    UNION ALL SELECT 'dataprotectionkeys', 3
) AS expected
LEFT JOIN (
    SELECT table_name, COUNT(*) AS actual_count
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
    GROUP BY table_name
) AS actual ON actual.table_name = expected.table_name
WHERE COALESCE(actual.actual_count, -1) <> expected.expected_count

UNION ALL

SELECT 'missing_or_incompatible_critical_column', expected.object_name
FROM (
    SELECT 'users.id' AS object_name, 'users' AS table_name, 'id' AS column_name,
           'varchar(255)' AS column_type, 'NO' AS is_nullable
    UNION ALL
    SELECT 'users.timestamp', 'users', 'timestamp', 'timestamp', 'NO'
    UNION ALL
    SELECT 'userpasskeys.credentialid', 'userpasskeys', 'credentialid',
           'varbinary(1024)', 'NO'
    UNION ALL
    SELECT 'userpasskeys.userid', 'userpasskeys', 'userid',
           'varchar(255)', 'NO'
    UNION ALL
    SELECT 'dataprotectionkeys.id', 'dataprotectionkeys', 'id',
           'int(11)', 'NO'
) AS expected
LEFT JOIN information_schema.columns AS actual
    ON actual.table_schema = DATABASE()
   AND actual.table_name = expected.table_name
   AND actual.column_name = expected.column_name
   AND actual.column_type = expected.column_type
   AND actual.is_nullable = expected.is_nullable
WHERE actual.column_name IS NULL

UNION ALL

SELECT 'missing_or_incompatible_critical_index', expected.object_name
FROM (
    SELECT 'users.usernameindex' AS object_name, 'users' AS table_name,
           'normalizedusername' AS column_name, 0 AS non_unique
    UNION ALL
    SELECT 'roles.rolenameindex', 'roles', 'normalizedname', 0
    UNION ALL
    SELECT 'userpasskeys.primary', 'userpasskeys', 'credentialid', 0
) AS expected
LEFT JOIN information_schema.statistics AS actual
    ON actual.table_schema = DATABASE()
   AND actual.table_name = expected.table_name
   AND actual.column_name = expected.column_name
   AND actual.non_unique = expected.non_unique
WHERE actual.index_name IS NULL

UNION ALL

SELECT 'openid_protocol_table_already_exists', actual.table_name
FROM information_schema.tables AS actual
WHERE actual.table_schema = DATABASE()
  AND actual.table_name IN ('applications', 'authorizations', 'scopes', 'tokens')

UNION ALL

SELECT 'new_migration_history_already_exists',
       '__sufficit_identity_migrations'
FROM information_schema.tables AS actual
WHERE actual.table_schema = DATABASE()
  AND actual.table_name = '__sufficit_identity_migrations';
