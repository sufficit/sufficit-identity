-- ============================================================================
-- 050-add-branding-themes.sql
-- Ensures the brandingthemes table exists and seeds the default Sufficit theme.
-- It may run after the canonical 001 script (where the EF migration is already
-- recorded) or after the additive legacy path. Repeated execution is safe.
-- ============================================================================

CREATE TABLE IF NOT EXISTS `brandingthemes` (
    `id`                 INT AUTO_INCREMENT PRIMARY KEY,
    `name`               VARCHAR(100)  NOT NULL,
    `isactive`           TINYINT(1)    NOT NULL,
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
    `createdat`          DATETIME(6)   NOT NULL,
    `updatedat`          DATETIME(6)   NOT NULL,
    INDEX `IX_brandingthemes_isactive` (`isactive`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed: default Sufficit theme (active)
INSERT INTO `brandingthemes` (
    `name`, `isactive`,
    `logourl`, `faviconurl`, `headericonurl`, `backgroundimageurl`,
    `brandcolor`, `brandhovercolor`, `brandsoftcolor`, `themecolor`,
    `title`, `brandname`, `brandsubtitle`,
    `createdat`, `updatedat`
) SELECT
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
WHERE NOT EXISTS (
    SELECT 1
    FROM `brandingthemes`
    WHERE `name` = 'Sufficit padrão'
);

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
SELECT '20260729025623_AddBrandingThemes', '10.0.10'
WHERE NOT EXISTS (
    SELECT 1
    FROM `__sufficit_identity_migrations`
    WHERE `MigrationId` = '20260729025623_AddBrandingThemes'
);
