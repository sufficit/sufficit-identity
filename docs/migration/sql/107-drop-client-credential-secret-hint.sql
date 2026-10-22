-- Phase 2 of migration DropClientCredentialSecretHint (after 106 and after the
-- new binaries run on every node): the fingerprint column goes.
START TRANSACTION;
ALTER TABLE `oauthclientcredentials` DROP COLUMN `secrethint`;

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
VALUES ('20261022170606_DropClientCredentialSecretHint', '10.0.13');

COMMIT;
