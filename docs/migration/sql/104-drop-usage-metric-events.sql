-- Phase 2 of migration AggregateUsageMetrics (after 103 and after the new
-- binaries run on every node, so no node still writes per-event rows): the
-- history moves into the aggregate as node "legacy", then the per-event table
-- and its user hashes are dropped.
START TRANSACTION;
INSERT INTO `identityapplicationusagedaily` (`day`, `node`, `clientid`, `eventtype`, `endpointtype`, `granttype`, `outcome`, `count`, `lastoccurredatutc`) SELECT DATE(`occurredatutc`), 'legacy', `clientid`, `eventtype`, `endpointtype`, COALESCE(`granttype`, ''), `outcome`, COUNT(*), MAX(`occurredatutc`) FROM `identityapplicationusageevents` GROUP BY DATE(`occurredatutc`), `clientid`, `eventtype`, `endpointtype`, COALESCE(`granttype`, ''), `outcome`;

DROP TABLE `identityapplicationusageevents`;

INSERT INTO `__sufficit_identity_migrations` (`MigrationId`, `ProductVersion`)
VALUES ('20261022141619_AggregateUsageMetrics', '10.0.13');

COMMIT;
