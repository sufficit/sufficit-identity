-- ============================================================
-- 020-migrate-identity-data.sql
-- Migra os dados do banco legado (identity / Duende) para o novo
-- banco OpenIddict (identity2). As tabelas ASP.NET Core Identity
-- tem schema IDENTICO entre os dois bancos (mesmas colunas lowercase).
-- Este script assume que identity2 ja tem o schema criado (001-create-empty-database.sql).
-- Re-executavel: todas as tabelas destino sao truncadas antes do INSERT.
-- ============================================================

-- Fonte: banco `identity` (legado Duende/Skoruba, no mesmo servidor MySQL)
-- Destino: banco `identity2` (novo OpenIddict, current database)

-- Desabilitar FK checks durante a migracao (TRUNCATE nao funciona com FKs)
SET FOREIGN_KEY_CHECKS = 0;

-- ---- Limpar destino (idempotente) ----
TRUNCATE `identity2`.`dataprotectionkeys`;
TRUNCATE `identity2`.`usertokens`;
TRUNCATE `identity2`.`userlogins`;
TRUNCATE `identity2`.`userclaims`;
TRUNCATE `identity2`.`userroles`;
TRUNCATE `identity2`.`roleclaims`;
TRUNCATE `identity2`.`roles`;
TRUNCATE `identity2`.`users`;

SET FOREIGN_KEY_CHECKS = 1;

-- ---- users ----
INSERT INTO `identity2`.`users` (
    `id`, `username`, `normalizedusername`, `email`, `normalizedemail`,
    `emailconfirmed`, `passwordhash`, `securitystamp`, `concurrencystamp`,
    `phonenumber`, `phonenumberconfirmed`, `twofactorenabled`,
    `lockoutend`, `lockoutenabled`, `accessfailedcount`, `timestamp`
)
SELECT
    `id`, `username`, `normalizedusername`, `email`, `normalizedemail`,
    `emailconfirmed`, `passwordhash`, `securitystamp`, `concurrencystamp`,
    `phonenumber`, `phonenumberconfirmed`, `twofactorenabled`,
    `lockoutend`, `lockoutenabled`, `accessfailedcount`, `timestamp`
FROM `identity`.`users`;

-- ---- roles ----
INSERT INTO `identity2`.`roles` (
    `id`, `name`, `normalizedname`, `concurrencystamp`
)
SELECT
    `id`, `name`, `normalizedname`, `concurrencystamp`
FROM `identity`.`roles`;

-- ---- roleclaims (0 rows no legado, mas copiar por completude) ----
INSERT INTO `identity2`.`roleclaims` (
    `id`, `roleid`, `claimtype`, `claimvalue`
)
SELECT
    `id`, `roleid`, `claimtype`, `claimvalue`
FROM `identity`.`roleclaims`;

-- ---- userclaims (5.084 rows, incluindo ~4.966 claims 'directive') ----
INSERT INTO `identity2`.`userclaims` (
    `id`, `userid`, `claimtype`, `claimvalue`
)
SELECT
    `id`, `userid`, `claimtype`, `claimvalue`
FROM `identity`.`userclaims`;

-- ---- userroles (21 rows; filtrar 1 role orfana) ----
INSERT INTO `identity2`.`userroles` (
    `userid`, `roleid`
)
SELECT
    ur.`userid`, ur.`roleid`
FROM `identity`.`userroles` ur
-- Filtrar apenas roles que existem (descarta a role orfana 233d2513-...)
INNER JOIN `identity`.`roles` r ON ur.`roleid` = r.`id`;

-- ---- userlogins (141 rows: Google 132, Facebook 9) ----
INSERT INTO `identity2`.`userlogins` (
    `loginprovider`, `providerkey`, `providerdisplayname`, `userid`
)
SELECT
    `loginprovider`, `providerkey`, `providerdisplayname`, `userid`
FROM `identity`.`userlogins`;

-- ---- usertokens (50 rows: reset tokens, 2FA tokens, etc.) ----
INSERT INTO `identity2`.`usertokens` (
    `userid`, `loginprovider`, `name`, `value`
)
SELECT
    `userid`, `loginprovider`, `name`, `value`
FROM `identity`.`usertokens`;

-- ---- dataprotectionkeys (24 keys — preserva o keyring para que cookies/tokens
--      protegidos pelo legado continuem validos durante a transicao) ----
INSERT INTO `identity2`.`dataprotectionkeys` (
    `id`, `friendlyname`, `xml`
)
SELECT
    `id`, `friendlyname`, `xml`
FROM `identity`.`dataprotectionkeys`;
