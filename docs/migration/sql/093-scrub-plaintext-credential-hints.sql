-- Scrub plaintext-derived client credential hints.
--
-- Until the fix in this release, oauthclientcredentials.secrethint stored the
-- LAST SIX CHARACTERS OF THE PLAINTEXT CLIENT SECRET, sitting in the same row
-- as the PBKDF2 hash of that same secret. Anyone able to read the table (a
-- backup copy, an over-broad DBA grant, SQL injection elsewhere) learns six
-- known characters per credential and can mount a far cheaper targeted attack
-- against the otherwise strong 210k-iteration hash.
--
-- New and rotated credentials now store an 8-character fingerprint derived
-- from the stored hash instead. Existing rows CANNOT be converted to the new
-- form, because that derivation needs the hash the row already has but the
-- application has no way to tell an old plaintext suffix apart from a new
-- fingerprint. Blanking is therefore the only safe remediation: the value is
-- cosmetic (it only helps an operator tell two credentials apart in the
-- management UI, where Label remains the primary identifier), and the UI
-- already degrades to "Valor protegido" when the hint is empty.
--
-- This script is intentionally idempotent and must be run only after taking
-- the normal production backup. It touches exactly one column: no credential
-- is revoked, no hash is altered, no client is reconfigured. Authentication is
-- unaffected — secrethint is never consulted when verifying a secret.
--
-- Run once on a single node; multimaster replication carries it to the others.

-- Report what is about to be cleared, so the operator sees the blast radius
-- before and after (expected: the "after" count is always zero).
SELECT COUNT(*) AS hints_to_scrub
FROM oauthclientcredentials
WHERE secrethint IS NOT NULL
  AND secrethint <> '';

UPDATE oauthclientcredentials
SET secrethint = ''
WHERE secrethint IS NOT NULL
  AND secrethint <> '';

SELECT COUNT(*) AS hints_remaining
FROM oauthclientcredentials
WHERE secrethint IS NOT NULL
  AND secrethint <> '';
