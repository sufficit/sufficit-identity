-- Phase 1 of migration SystemUsersAsOrdinaryUsers: audit events gain their
-- own expiry (`expiresatutc`; null = default retention, 9999-12-31 = never).
-- Safe with the previous binaries (they do not map the column). Apply BEFORE
-- deploying the binaries; apply 102 right AFTER they run on every node.
START TRANSACTION;
ALTER TABLE `managementauditevents` ADD `expiresatutc` datetime(6) NULL;

CREATE INDEX `IX_managementauditevents_expiresatutc` ON `managementauditevents` (`expiresatutc`);

COMMIT;
