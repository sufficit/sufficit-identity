# Fleet access for Acesso Point (aicontrol entitlement)

Date: 2026-11-12. Requested by the owner (Hugo) for the Acesso Point voice agents rollout
(`sufficit-fleet/docs/plans/PLAN-CUSTOMER-VOICE-AGENTS.md`).

## Problem

User `contato@acessopoint.com.br` (`82c20390-5387-473f-8ea5-a512250795c3`) signed in to Identity, but Fleet answered
`/account/denied`: no authorized fleet. Fleet grants a company fleet only through `aicontrol:<context>`; `aiuser`
admits the user's own personal fleet only. The user had `aiuser:b6e311a0…`, not `aicontrol`.

## Change

Direct insert on the Galera primary (`eveo-data`, database `identity`, table `userclaims`), same format as the
existing grant held by another Acesso Point user (`2ab8dd69…`). The management API was not reachable from this session
(Identity MCP disconnected).

```sql
INSERT INTO userclaims (userid, claimtype, claimvalue)
SELECT '82c20390-5387-473f-8ea5-a512250795c3', 'entitlements', 'aicontrol:b6e311a0cf074319a9302c0ada96f047'
FROM dual WHERE NOT EXISTS (SELECT 1 FROM userclaims WHERE userid = '82c20390-5387-473f-8ea5-a512250795c3'
  AND claimvalue = 'aicontrol:b6e311a0cf074319a9302c0ada96f047');
```

Result: row id 42311. Scope: only the Acesso Point context `b6e311a0-cf07-4319-a930-2c0ada96f047`.

## Effect and rollback

The user must sign in again for the new claim. Rollback: `DELETE FROM userclaims WHERE id = 42311;`.
