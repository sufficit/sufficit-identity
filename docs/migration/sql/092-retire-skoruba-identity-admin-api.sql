-- Retire the superseded Skoruba Admin API scope.
--
-- This script is intentionally idempotent and must be run only after taking
-- the normal production backup. It removes the scope from client permission
-- arrays and persisted authorizations, revokes tokens issued from those
-- authorizations, then deletes the exact OpenIddict scope row. No other scope
-- or client permission is changed.

SET @retired_scope := 'skoruba_identity_admin_api';
SET @retired_permission := CONCAT('scp:', @retired_scope);

START TRANSACTION;

-- Revoke any currently usable tokens tied to an authorization that granted
-- the retired scope. Encrypted token payloads are deliberately not inspected.
UPDATE `tokens` t
JOIN `authorizations` a ON a.`id` = t.`authorization_id`
SET t.`status` = 'revoked'
WHERE JSON_SEARCH(a.`scopes`, 'one', @retired_scope) IS NOT NULL
  AND t.`status` = 'valid';

-- Remove the retired grant from persisted authorizations while retaining all
-- unrelated consented scopes for audit continuity.
UPDATE `authorizations`
SET `scopes` = JSON_REMOVE(
    `scopes`,
    JSON_UNQUOTE(JSON_SEARCH(`scopes`, 'one', @retired_scope)))
WHERE JSON_SEARCH(`scopes`, 'one', @retired_scope) IS NOT NULL;

-- Remove only the retired scope permission from every application.
UPDATE `applications`
SET `permissions` = JSON_REMOVE(
    `permissions`,
    JSON_UNQUOTE(JSON_SEARCH(`permissions`, 'one', @retired_permission)))
WHERE JSON_SEARCH(`permissions`, 'one', @retired_permission) IS NOT NULL;

-- Delete exactly the retired scope; the name and id predicates prevent a
-- stale operational script from deleting a newly-created unrelated record.
DELETE FROM `scopes`
WHERE `id` = 'bb4817908ab211f19497f29960f8a788'
  AND `name` = @retired_scope;

COMMIT;
