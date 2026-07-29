-- ============================================================================
-- 050-add-branding-themes.sql
-- Creates the brandingthemes table and seeds the default Sufficit theme.
-- Run against the identity2 database after 001-create-empty-database.sql.
-- ============================================================================

CREATE TABLE IF NOT EXISTS `brandingthemes` (
    `id`                 INT AUTO_INCREMENT PRIMARY KEY,
    `name`               VARCHAR(100)  NOT NULL,
    `isactive`           TINYINT(1)    NOT NULL DEFAULT 0,
    `logourl`            VARCHAR(512)  NULL,
    `faviconurl`         VARCHAR(512)  NULL,
    `headericonurl`      VARCHAR(512)  NULL,
    `backgroundimageurl` VARCHAR(512)  NULL,
    `brandcolor`         VARCHAR(7)    NULL,
    `brandhovercolor`    VARCHAR(7)    NULL,
    `brandsoftcolor`     VARCHAR(7)    NULL,
    `themecolor`         VARCHAR(7)    NULL,
    `title`              VARCHAR(200)  NULL,
    `brandname`          VARCHAR(100)  NULL,
    `brandsubtitle`      VARCHAR(100)  NULL,
    `createdat`          DATETIME      NOT NULL,
    `updatedat`          DATETIME      NOT NULL,
    INDEX `IX_brandingthemes_isactive` (`isactive`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed: default Sufficit theme (active)
INSERT INTO `brandingthemes` (
    `name`, `isactive`,
    `logourl`, `faviconurl`, `headericonurl`, `backgroundimageurl`,
    `brandcolor`, `brandhovercolor`, `brandsoftcolor`, `themecolor`,
    `title`, `brandname`, `brandsubtitle`,
    `createdat`, `updatedat`
) VALUES (
    'Sufficit padrão',
    1,
    '_content/Sufficit.Identity.UI/img/logo-full.png',
    '_content/Sufficit.Identity.UI/img/favicon.png',
    '_content/Sufficit.Identity.UI/img/header-icon.png',
    '_content/Sufficit.Identity.UI/img/login-bg.jpg',
    '#cc0000',
    '#a30000',
    '#fbe9e9',
    '#cc0000',
    'Sufficit Identity',
    'Sufficit',
    'Identity',
    UTC_TIMESTAMP(),
    UTC_TIMESTAMP()
);
