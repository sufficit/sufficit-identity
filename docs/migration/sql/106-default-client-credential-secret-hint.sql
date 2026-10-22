-- Phase 1 of migration DropClientCredentialSecretHint: the console no longer
-- shows anything derived from a client secret (plan E2), and the new binaries
-- no longer write `secrethint`. A default lets them insert while the column
-- still exists; the previous binaries keep writing it. Apply BEFORE deploying
-- the binaries; apply 107 right AFTER they run on every node.
ALTER TABLE `oauthclientcredentials` ALTER COLUMN `secrethint` SET DEFAULT '';
