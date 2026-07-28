-- ============================================================
-- 030-migrate-openiddict-clients.sql
-- Converte clients/scope do banco legado (identity / Duende) para o
-- formato OpenIddict (identity2).
-- ============================================================

SET FOREIGN_KEY_CHECKS = 0;
TRUNCATE `identity2`.`applications`;
TRUNCATE `identity2`.`scopes`;
SET FOREIGN_KEY_CHECKS = 1;

-- ============================================================
-- SCOPES
-- ============================================================
INSERT INTO `identity2`.`scopes` (`id`, `concurrency_token`, `description`, `display_name`, `name`, `resources`)
SELECT REPLACE(UUID(),'-',''), REPLACE(UUID(),'-',''), s.`description`, s.`displayname`, s.`name`, '[]'
FROM `identity`.`apiscopes` s WHERE s.`enabled` = 1;

INSERT IGNORE INTO `identity2`.`scopes` (`id`, `concurrency_token`, `name`, `display_name`, `resources`)
VALUES
    (REPLACE(UUID(),'-',''), REPLACE(UUID(),'-',''), 'openid', 'OpenID Connect', '[]'),
    (REPLACE(UUID(),'-',''), REPLACE(UUID(),'-',''), 'profile', 'User profile', '[]'),
    (REPLACE(UUID(),'-',''), REPLACE(UUID(),'-',''), 'email', 'Email address', '[]'),
    (REPLACE(UUID(),'-',''), REPLACE(UUID(),'-',''), 'roles', 'User roles', '[]'),
    (REPLACE(UUID(),'-',''), REPLACE(UUID(),'-',''), 'address', 'Postal address', '[]'),
    (REPLACE(UUID(),'-',''), REPLACE(UUID(),'-',''), 'offline_access', 'Offline access', '[]');

UPDATE `identity2`.`scopes` sc
SET sc.`resources` = COALESCE((
    SELECT CONCAT('[', GROUP_CONCAT(CONCAT('"', ar.`name`, '"')), ']')
    FROM `identity`.`apiresourcescopes` ars
    INNER JOIN `identity`.`apiresources` ar ON ars.`apiresourceid` = ar.`id`
    WHERE ars.`scope` = sc.`name` AND ar.`enabled` = 1
), '[]')
WHERE sc.`name` IN (SELECT `name` FROM `identity`.`apiscopes`);

-- ============================================================
-- APPLICATIONS (dados basicos)
-- ============================================================
INSERT INTO `identity2`.`applications` (
    `id`, `application_type`, `client_id`, `client_secret`, `client_type`,
    `concurrency_token`, `consent_type`, `display_name`,
    `permissions`, `post_logout_redirect_uris`, `redirect_uris`,
    `requirements`, `settings`
)
SELECT
    REPLACE(UUID(),'-',''), 'web', c.`clientid`,
    (SELECT `value` FROM `identity`.`clientsecrets` cs WHERE cs.`clientid` = c.`id` AND cs.`type` = 'SharedSecret' ORDER BY cs.`id` LIMIT 1),
    CASE WHEN c.`requireclientsecret` = 1 THEN 'confidential' ELSE 'public' END,
    REPLACE(UUID(),'-',''),
    CASE WHEN c.`requireconsent` = 1 THEN 'explicit' ELSE 'implicit' END,
    c.`clientname`, '[]',
    COALESCE((SELECT CONCAT('[', GROUP_CONCAT(CONCAT('"', REPLACE(p.`postlogoutredirecturi`, '"', '\\"'), '"')), ']') FROM `identity`.`clientpostlogoutredirecturis` p WHERE p.`clientid` = c.`id`), '[]'),
    COALESCE((SELECT CONCAT('[', GROUP_CONCAT(CONCAT('"', REPLACE(r.`redirecturi`, '"', '\\"'), '"')), ']') FROM `identity`.`clientredirecturis` r WHERE r.`clientid` = c.`id`), '[]'),
    CASE WHEN c.`requirepkce` = 1 THEN '["ft:pkce"]' ELSE '[]' END,
    CONCAT('{"access_token_lifetime":"', c.`accesstokenlifetime`, '","id_token_lifetime":"', c.`identitytokenlifetime`, '","authorization_code_lifetime":"', c.`authorizationcodelifetime`, '","absolute_refresh_token_lifetime":"', c.`absoluterefreshtokenlifetime`, '","sliding_refresh_token_lifetime":"', c.`slidingrefreshtokenlifetime`, '"}')
FROM `identity`.`clients` c
WHERE c.`enabled` = 1 AND c.`clientid` IS NOT NULL AND c.`clientid` != '';

-- ============================================================
-- PERMISSIONS: tabela temporaria + UPDATE por JOIN
-- ============================================================

DROP TEMPORARY TABLE IF EXISTS `_migrate_perms`;
CREATE TEMPORARY TABLE `_migrate_perms` (
    `client_id` varchar(100),
    `permissions` longtext
);

-- Endpoint + grant type permissions
INSERT INTO `_migrate_perms` (`client_id`, `permissions`)
SELECT
    c.`clientid`,
    CONCAT('[', GROUP_CONCAT(DISTINCT perm SEPARATOR ','), ']')
FROM `identity`.`clients` c
LEFT JOIN (
    SELECT cgt.`clientid` AS cid,
        CONCAT('"', CASE cgt.`granttype`
            WHEN 'authorization_code' THEN 'gt:authorization_code'
            WHEN 'client_credentials' THEN 'gt:client_credentials'
            WHEN 'password' THEN 'gt:password'
            WHEN 'refresh_token' THEN 'gt:refresh_token'
            WHEN 'urn:ietf:params:oauth:grant-type:device_code' THEN 'gt:device_code'
            ELSE CONCAT('gt:', cgt.`granttype`) END, '"') AS perm
    FROM `identity`.`clientgranttypes` cgt
    WHERE cgt.`granttype` NOT IN ('implicit','hybrid')
) gt ON gt.`cid` = c.`id`
WHERE c.`enabled` = 1 AND c.`clientid` IS NOT NULL AND c.`clientid` != ''
GROUP BY c.`clientid`;

-- Adicionar endpoint permissions e rst:code
UPDATE `_migrate_perms` mp
INNER JOIN `identity`.`clients` c ON c.`clientid` = mp.`client_id`
SET mp.`permissions` = CONCAT(
    SUBSTRING(mp.`permissions`, 1, LENGTH(mp.`permissions`) - 1),
    IF(mp.`permissions` != '[]', ',', ''),
    CASE
        WHEN EXISTS (SELECT 1 FROM `identity`.`clientgranttypes` g WHERE g.`clientid` = c.`id` AND g.`granttype` != 'implicit')
            THEN '"ept:token",' ELSE '' END,
    CASE
        WHEN EXISTS (SELECT 1 FROM `identity`.`clientgranttypes` g WHERE g.`clientid` = c.`id` AND g.`granttype` IN ('authorization_code','hybrid','implicit'))
            THEN '"ept:authorization",' ELSE '' END,
    CASE
        WHEN EXISTS (SELECT 1 FROM `identity`.`clientgranttypes` g WHERE g.`clientid` = c.`id` AND g.`granttype` = 'authorization_code')
            THEN '"ept:end_session","rst:code",' ELSE '' END,
    ']'
);

-- Adicionar scope permissions
UPDATE `_migrate_perms` mp
INNER JOIN `identity`.`clients` c ON c.`clientid` = mp.`client_id`
SET mp.`permissions` = CONCAT(
    SUBSTRING(mp.`permissions`, 1, LENGTH(mp.`permissions`) - 1),
    IF(mp.`permissions` NOT LIKE '%[]' AND RIGHT(mp.`permissions`, 2) != '[]', ',', ''),
    COALESCE((
        SELECT GROUP_CONCAT(DISTINCT CONCAT('"scp:', REPLACE(cs.`scope`, '"', '\\"'), '"') SEPARATOR ',')
        FROM `identity`.`clientscopes` cs WHERE cs.`clientid` = c.`id`
    ), ''),
    ']'
)
WHERE EXISTS (SELECT 1 FROM `identity`.`clientscopes` cs WHERE cs.`clientid` = c.`id`);

-- Limpar virgulas extras
UPDATE `_migrate_perms` SET `permissions` = REPLACE(`permissions`, ',]', ']');
UPDATE `_migrate_perms` SET `permissions` = REPLACE(`permissions`, '[,', '[');
UPDATE `_migrate_perms` SET `permissions` = REPLACE(`permissions`, ',,', ',');

-- Garantir que TODOS os clients tem entrada na temp table (mesmo os
-- que so tinham implicit/hybrid no legado — eles pegarao apenas as
-- scope permissions no update abaixo).
INSERT IGNORE INTO `_migrate_perms` (`client_id`, `permissions`)
SELECT `client_id`, '[]' FROM `identity2`.`applications`;

-- Aplicar permissions ao destino
UPDATE `identity2`.`applications` a
INNER JOIN `_migrate_perms` mp ON mp.`client_id` = a.`client_id`
SET a.`permissions` = mp.`permissions`;

DROP TEMPORARY TABLE IF EXISTS `_migrate_perms`;

-- ============================================================
-- PASSO 4: Garantir que clients com implicit/hybrid do legado
-- tenham gt:authorization_code (OAuth 2.1 nao suporta esses flows)
-- ============================================================
UPDATE `identity2`.`applications` a
SET a.`permissions` = CASE
    WHEN a.`permissions` IS NULL OR a.`permissions` = '[]' THEN
        '["gt:authorization_code","ept:token","ept:authorization","ept:end_session","rst:code"]'
    WHEN a.`permissions` NOT LIKE '%gt:authorization_code%' THEN
        CONCAT(
            SUBSTRING(a.`permissions`, 1, LENGTH(a.`permissions`) - 1),
            ',"gt:authorization_code","ept:token","ept:authorization","ept:end_session","rst:code"]'
        )
    ELSE a.`permissions`
END
WHERE a.`redirect_uris` != '[]';
