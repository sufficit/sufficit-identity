# RFC 9449 — Demonstrating Proof of Possession (DPoP)

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **B — Substantial** |
| Origin | In-house — OpenIddict 7.x does not implement DPoP |
| Spec | https://www.rfc-editor.org/rfc/rfc9449 |

This is the extension with the most in-house code in the repository: 37
references to the RFC in `src/sts/Dpop/`.

## Components

| File | Role |
|---|---|
| `DpopProofValidator.cs` | Validation of the JWT proof |
| `DpopTokenHandlers.cs` | `AttachDpopConfirmation`, `AttachDpopTokenType`, `ExtractDpopUserInfoToken`, `ValidateDpopAccessTokenProof` |
| `DatabaseDpopReplayCache.cs` | Persisted, atomic `jti` cache |
| `DistributedDpopReplayCache.cs` | Distributed layer |
| `DatabaseDpopNonceStore.cs`, `DistributedDpopNonceStore.cs` | Nonce issuance and validation |
| `DpopValidationHandlers.cs` | Token validation side |

Registered in `src/sts/OpenIddictServerConfiguration.cs:334-340` and
`src/sts/ServiceCollectionExtensions.cs:798-835`.

## Proof validation

Actual order in the code (`src/sts/Dpop/DpopProofValidator.cs`):

| # | Check | § |
|---|---|---|
| 1 | `typ` exactly `dpop+jwt` | 4.2 |
| 2 | `alg` restricted to `ES256` or `RS256`, matching what discovery advertises | 4.2 |
| 3 | Public key extracted from the `jwk` header; signature verified against it | 4.3 |
| 4 | `htm` equal to the HTTP method, case-sensitive comparison | 4.3 |
| 5 | `htu` equal to the URL without query or fragment | 4.3 |
| 6 | `iat` at most 60 s in the future and within the `jti` cache window | 4.3 |
| 7 | `exp` present and in the future | — |
| 8 | `jti` unseen, checked against the persisted cache | 4.3 |
| 9 | `ath` = base64url(SHA-256(access_token)) when a token is present | 4.2 |
| 10 | `nonce` equal to the one issued, when required | 8 |

Step 6 matters: relying only on the `jti` cache would leave a captured proof
usable until the cache entry expired. The time window closes that off.

## Replay across replicas

The `jti` cache is **not** in-memory by default: `DatabaseDpopReplayCache` is
registered as `IAtomicDpopReplayCache` and persists to `dpopreplayentries`
(`src/sts/ServiceCollectionExtensions.cs:799-803`). There is an in-process
implementation, but the constructor that uses it emits a warning that it is
unsafe in a multi-replica setup. With three nodes sharing the database,
replay is blocked across all of them.

## Nonce dance

In `TokenGrantDispatcher.DispatchAsync` (`src/sts/Grants/TokenGrants.cs`),
when `Dpop:RequireNonce`:

1. The nonce partition is `path | client_id | key thumbprint`
   (`BuildDpopNoncePartition`). Anonymous traffic does not rotate another
   client's challenge.
2. If the presented nonce is not valid, the proof is validated **without**
   the nonce; only a cryptographically valid proof receives a new nonce,
   returned in `DPoP-Nonce` with the `use_dpop_nonce` error.

## Token binding

| Moment | Behavior |
|---|---|
| Issuance | `cnf.jkt` attached by `AttachDpopConfirmation`; `token_type` becomes `DPoP` |
| Refresh | The **original** binding is preserved; the token cannot be rebound to another key (`UserTokenGrantsHandler`) |
| Authorization code | Under FAPI 2.0, `dpop_jkt` authenticated at PAR is preserved in the code's principal (`AuthorizationController.cs`) |
| Userinfo | `ExtractDpopUserInfoToken` + `ath` verification |
| Conflict with mTLS | Rejected by `RejectCombinedDpopAndMtlsSenderConstraints` |

## Configuration

| Key | Default | Effect |
|---|---|---|
| `Dpop:Enabled` | `false` | Turns on the extension and its discovery advertisement |
| `Dpop:RequireForAllClients` | `false` | Proof mandatory for everyone |
| `Dpop:RequireNonce` | `false` | Activates the nonce dance |

## Gaps

- No mandatory proof per client: the requirement is global or via the FAPI
  profile.
- `dpop_bound_access_tokens` as per-client metadata (§5.2) is not registered.

## Tests

`DpopTests`, `SenderConstraintTests`, `DistributedStoreTests`,
`FapiJarmTests`.
