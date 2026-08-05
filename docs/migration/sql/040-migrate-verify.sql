-- ============================================================
-- 040-migrate-verify.sql
-- Verificacoes de integridade pos-migracao.
-- Cada query retorna uma tabela de comparacao: legado vs novo.
-- ============================================================

-- Pattern: SELECT 'descricao', count_legado, count_novo

SELECT '=== VERIFICACAO DE MIGRACAO ===' AS '';
SELECT '' AS '';

-- ---- Users ----
SELECT 'users' AS tabela,
    (SELECT COUNT(*) FROM `identity`.`users`) AS legado,
    (SELECT COUNT(*) FROM `identity2`.`users`) AS novo,
    (SELECT COUNT(*) FROM `identity`.`users`) - (SELECT COUNT(*) FROM `identity2`.`users`) AS diff;

-- ---- Roles ----
SELECT 'roles' AS tabela,
    (SELECT COUNT(*) FROM `identity`.`roles`) AS legado,
    (SELECT COUNT(*) FROM `identity2`.`roles`) AS novo,
    (SELECT COUNT(*) FROM `identity`.`roles`) - (SELECT COUNT(*) FROM `identity2`.`roles`) AS diff;

-- ---- UserClaims (incluindo directive) ----
SELECT 'userclaims (total)' AS tabela,
    (SELECT COUNT(*) FROM `identity`.`userclaims`) AS legado,
    (SELECT COUNT(*) FROM `identity2`.`userclaims`) AS novo,
    (SELECT COUNT(*) FROM `identity`.`userclaims`) - (SELECT COUNT(*) FROM `identity2`.`userclaims`) AS diff;

SELECT 'userclaims (directive)' AS tabela,
    (SELECT COUNT(*) FROM `identity`.`userclaims` WHERE `claimtype` = 'directive') AS legado,
    (SELECT COUNT(*) FROM `identity2`.`userclaims` WHERE `claimtype` = 'directive') AS novo,
    (SELECT COUNT(*) FROM `identity`.`userclaims` WHERE `claimtype` = 'directive')
    - (SELECT COUNT(*) FROM `identity2`.`userclaims` WHERE `claimtype` = 'directive') AS diff;

-- ---- UserRoles (filtrado: legado tem 1 orfana) ----
SELECT 'userroles (total legado)' AS tabela,
    COUNT(*) AS legado, NULL AS novo, NULL AS diff
    FROM `identity`.`userroles`
UNION ALL
SELECT 'userroles (validos)' AS tabela,
    COUNT(*) AS legado,
    (SELECT COUNT(*) FROM `identity2`.`userroles`) AS novo,
    COUNT(*) - (SELECT COUNT(*) FROM `identity2`.`userroles`) AS diff
    FROM `identity`.`userroles` ur
    INNER JOIN `identity`.`roles` r ON ur.`roleid` = r.`id`;

-- ---- UserLogins ----
SELECT 'userlogins' AS tabela,
    (SELECT COUNT(*) FROM `identity`.`userlogins`) AS legado,
    (SELECT COUNT(*) FROM `identity2`.`userlogins`) AS novo,
    (SELECT COUNT(*) FROM `identity`.`userlogins`) - (SELECT COUNT(*) FROM `identity2`.`userlogins`) AS diff;

SELECT 'userlogins (Google)' AS tabela,
    (SELECT COUNT(*) FROM `identity`.`userlogins` WHERE `loginprovider` = 'Google') AS legado,
    (SELECT COUNT(*) FROM `identity2`.`userlogins` WHERE `loginprovider` = 'Google') AS novo,
    0 AS diff;

SELECT 'userlogins (Facebook)' AS tabela,
    (SELECT COUNT(*) FROM `identity`.`userlogins` WHERE `loginprovider` = 'Facebook') AS legado,
    (SELECT COUNT(*) FROM `identity2`.`userlogins` WHERE `loginprovider` = 'Facebook') AS novo,
    0 AS diff;

-- ---- UserTokens ----
SELECT 'usertokens' AS tabela,
    (SELECT COUNT(*) FROM `identity`.`usertokens`) AS legado,
    (SELECT COUNT(*) FROM `identity2`.`usertokens`) AS novo,
    (SELECT COUNT(*) FROM `identity`.`usertokens`) - (SELECT COUNT(*) FROM `identity2`.`usertokens`) AS diff;

-- ---- DataProtectionKeys ----
SELECT 'dataprotectionkeys' AS tabela,
    (SELECT COUNT(*) FROM `identity`.`dataprotectionkeys`) AS legado,
    (SELECT COUNT(*) FROM `identity2`.`dataprotectionkeys`) AS novo,
    (SELECT COUNT(*) FROM `identity`.`dataprotectionkeys`) - (SELECT COUNT(*) FROM `identity2`.`dataprotectionkeys`) AS diff;

-- ---- Applications (Clients) ----
SELECT 'applications (novo)' AS tabela,
    (SELECT COUNT(*) FROM `identity`.`clients` WHERE `enabled` = 1 AND `clientid` IS NOT NULL AND `clientid` != '') AS legado,
    (SELECT COUNT(*) FROM `identity2`.`applications`) AS novo,
    0 AS diff;

-- ---- Scopes ----
SELECT 'scopes (novo)' AS tabela,
    (SELECT COUNT(*) FROM `identity`.`apiscopes` WHERE `enabled` = 1) AS legado,
    (SELECT COUNT(*) FROM `identity2`.`scopes`) AS novo,
    0 AS diff;

-- ---- Integridade: usuarios sem role valida ----
SELECT 'users_sem_role_em_users2' AS verificacao,
    (SELECT COUNT(DISTINCT ur.userid)
     FROM `identity2`.`userroles` ur
     LEFT JOIN `identity2`.`users` u ON ur.`userid` = u.`id`
     WHERE u.`id` IS NULL) AS resultado;
-- Resultado deve ser 0

-- ---- Integridade: userclaims sem usuario valido ----
SELECT 'userclaims_sem_usuario' AS verificacao,
    (SELECT COUNT(DISTINCT uc.userid)
     FROM `identity2`.`userclaims` uc
     LEFT JOIN `identity2`.`users` u ON uc.`userid` = u.`id`
     WHERE u.`id` IS NULL) AS resultado;
-- Resultado deve ser 0

-- ---- Amostra: applications migradas com permissoes ----
SELECT 'applications_migradas_amostra' AS '';
SELECT `client_id`, `client_type`, `consent_type`,
    JSON_LENGTH(`permissions`) AS num_permissions,
    JSON_LENGTH(`redirect_uris`) AS num_redirects,
    `requirements`
FROM `identity2`.`applications`
LIMIT 10;

-- ---- Amostra: scopes migrados ----
SELECT 'scopes_migrados_amostra' AS '';
SELECT `name`, `display_name`, `resources`
FROM `identity2`.`scopes`
ORDER BY `name`;
