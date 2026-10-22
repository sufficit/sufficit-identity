-- Phase 2 of migration SystemUsersAsOrdinaryUsers (after 101 and after the
-- new binaries run on every node: the previous ones read `systemusers` on
-- every sign-in). System users become ordinary users without e-mail or
-- password: their origin moves to a permanent audit event, their disabled
-- state to the ordinary lockout, and the marker table is dropped.
START TRANSACTION;
UPDATE `managementauditevents` SET `expiresatutc` = '9999-12-31 00:00:00' WHERE `reasoncode` = 'system_user_created';

INSERT INTO `managementauditevents` (`occurredatutc`, `operatorsubject`, `capability`, `resourcetype`, `resourceid`, `authorizationoutcome`, `operationoutcome`, `reasoncode`, `correlationid`, `expiresatutc`) SELECT s.`createdatutc`, s.`createdby`, 'identity.users.create', 'user', s.`userid`, 'allowed', 'succeeded', 'system_user_created', COALESCE(s.`correlationid`, 'migration-system-users'), '9999-12-31 00:00:00' FROM `systemusers` s WHERE NOT EXISTS (SELECT 1 FROM `managementauditevents` e WHERE e.`resourceid` = s.`userid` AND e.`reasoncode` = 'system_user_created');

UPDATE `users` u JOIN `systemusers` s ON s.`userid` = u.`id` SET u.`lockoutenabled` = 1, u.`lockoutend` = '9999-12-31 00:00:00' WHERE s.`disabledatutc` IS NOT NULL;

ALTER TABLE `systemuserenrollments` DROP FOREIGN KEY `FK_systemuserenrollments_systemusers_userid`;

DROP TABLE `systemusers`;

ALTER TABLE `systemuserenrollments` ADD CONSTRAINT `FK_systemuserenrollments_users_userid` FOREIGN KEY (`userid`) REFERENCES `users` (`id`) ON DELETE CASCADE;

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
VALUES ('20261022140929_SystemUsersAsOrdinaryUsers', '10.0.13');

COMMIT;
