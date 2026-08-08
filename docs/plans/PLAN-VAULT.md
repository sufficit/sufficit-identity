# PLAN-VAULT — Internal Secret Vault for sufficit-identity

> **Status:** Phases 1–3 implemented (opt-in signing/JWKS) · **Owner:** Sufficit · **Created:** 2026-08-05
> **Target version:** `0.4.0-alpha` · **Prerequisite:** none (greenfield module)

## 1. Motivation

sufficit-identity currently has **no at-rest encryption** for secrets it stores or
operates on, and **no abstraction** between "where a secret comes from" and
"who consumes it". Concrete gaps confirmed in the codebase:

| Gap | Location | Risk |
|-----|----------|------|
| SSF stream push tokens stored **plaintext** in DB | `src/sts/SharedSignals/SsfStreamStore.cs:113` (`SsfStream.Authorization`) | DB dump leaks every receiver bearer token |
| DPoP nonces, CIBA pending requests **plaintext** in `IDistributedCache` | `src/sts/Dpop/DistributedDpopNonceStore.cs:54`, `src/sts/Ciba/DistributedCibaPendingRequestStore.cs:170` | Cache backend (Redis) compromise exposes transient auth state |
| Token-signing PFX password in **env var / config** | `src/server/appsettings.json.template:42-51`, loaded at `ServiceCollectionExtensions.cs:600` | Env var leak = full signing-key compromise |
| Data Protection keyring encrypted **only by the signing cert** | `ServiceCollectionExtensions.cs:168-176` | If the PFX leaks, the whole DP ring leaks with it |
| TLS certs **self-signed, 365-day, no rotation** | `deploy/gen-cert.sh` | Acceptable for dev; a production liability |
| No `ISecretStore` / `IKeyVault` abstraction | everywhere reads `IOptions` / env var directly | Cannot swap source without touching consumers |

This plan defines a **self-contained internal vault** — not a dependency on
OpenBao/Vault/AWS KMS — that closes these gaps with patterns proven by
Bitwarden, age, sops, and the cloud KMS envelope model, while keeping the
"clone + `docker compose up`" zero-dependency onboarding promise from `ONBOARD.md`.

## 2. Comparative survey — what the mature projects do

### 2.1 Bitwarden / vaultwarden (client-side zero-knowledge vault)

- **Key chain:** master password → **Argon2id** (or PBKDF2-SHA256 600k iters),
  salt = lowercase email → 256-bit Master Key → **HKDF-SHA256 stretch to 512 bits**
  → split into AES-256 enc key + HMAC-SHA256 MAC key.
- A fresh **512-bit User Symmetric Key** (CSPRNG) is the real vault key; it is
  wrapped (AES-256-CBC + HMAC) by the stretched master key and stored server-side
  as the "Protected Symmetric Key". The server never sees it in plaintext.
- **Per-item Cipher Key** (64 bytes CSPRNG) per secret; cipher key wrapped by the
  user key (personal) or org key (shared). Enables per-item rotation + sharing.
- **Org/collection sharing** via RSA-2048 OAEP-wrapped org keys — each member gets
  the org key wrapped with their own RSA public key.
- **Key rotation:** generate new user key → re-encrypt every cipher key + RSA
  private key + org keys under the new key → re-wrap user key under stretched
  master. Destructive across stale sessions.

### 2.2 HashiCorp Vault / OpenBao — Transit engine (encryption-as-a-service)

- **Keys never leave the barrier.** App sends plaintext → Transit encrypts inside
  the process and returns ciphertext; app stores the ciphertext in its own DB.
- **Named, versioned keys.** `transit/keys/my-key` holds a keyring of versions
  (v1, v2, …). Rotation = new version; `min_decryption_version` retires old ones.
- **Self-describing ciphertext:** `vault:v<N>:<base64(iv||ct||tag)>` — the version
  tag is embedded in every blob, so decryption picks the right key version for free.
- AEAD ciphers (`aes256-gcm96`, `chacha20-poly1305`); convergent encryption optional.
- Contrast with **KV engine** (a *store* of named secrets encrypted at rest) —
  Transit is a *function*, stateless for data.

### 2.3 age (file envelope) / sops (per-field envelope)

- **age:** every file gets a fresh 128-bit **file key**; payload = ChaCha20-Poly1305
  chunked at 64 KiB; the file key is **wrapped independently per recipient**
  (X25519 ECDH → HKDF → ChaCha20-Poly1305). Header carries an **HMAC-SHA256 over
  the whole header** (derived from the file key) for fail-fast tamper detection
  *before* any decryption attempt.
- **sops:** one **256-bit data key** per document; every leaf value encrypted
  independently (AES-256-GCM, per-value nonce); the data key is **wrapped by
  every configured master** (KMS / age / PGP), any one suffices to recover it.
  A structural **HMAC over the unencrypted keys** (`__sops__.mac`) catches
  ciphertext-swapping between fields. `sops updatekeys` re-wraps the *same* data
  key under new masters without re-encrypting values.

### 2.4 AWS KMS / GCP KMS / Azure Key Vault (envelope standard)

- **DEK (Data Encryption Key)** encrypts data, generated locally per write,
  never persisted in plaintext.
- **KEK (Key Encryption Key)** wraps the DEK; lives in the HSM, never leaves.
- `GenerateDataKey` returns `plaintext_DEK || DEK_wrapped_by_KEK`; app encrypts,
  stores `ciphertext || wrapped_DEK`, discards the plaintext DEK.
- **Encryption context / AAD** (AWS ESDK) is cryptographically bound to the
  ciphertext — ties a secret to its scope (tenant, purpose).

### 2.5 Our own sufficit-ai (reference internal project)

- **Abstractions worth reusing:** `IProviderCredentials`,
  `IProviderCredentialSink`, `ProviderCredentialSnapshot` (`src/core/`) — clean
  separation of "what a credential looks like" vs "how it's seeded into an adapter".
- **Separation of concerns in the entity:** `AIProviderItem.Token` (raw auth
  secret), `AuthPayload` (provider-origin OAuth bag), `SettingsPayload` (local
  operator config) — three distinct sensitivity tiers in one record. Good model.
- **Gap to fix:** tokens are stored **plaintext** in the DB (`AIProviderItem.Token`)
  and DataProtection keys are **plaintext XML on disk**
  (`api/Startup.cs:184-187` — `PersistKeysToFileSystem` with no
  `ProtectKeysWithCertificate`). This is exactly the gap the vault should close,
  and sufficit-ai can adopt the same vault module once it exists.

## 3. Design — what we borrow and what we skip

### 3.0 Certificates: who is who (TLS vs signing vs DP)

A common confusion is treating "the cert" as one thing. sufficit-identity deals
with **three distinct certificates**, only one of which has anything to do with
Let's Encrypt. The vault touches the second one, never the first.

| Cert | Purpose | Who issues it | Validity | Where it lives | Renewal |
|------|---------|---------------|----------|----------------|---------|
| **TLS** | Encrypt browser↔server traffic (HTTPS) | **Let's Encrypt** (or a paid CA), via HTTP-01/DNS-01 challenge | 90 days (Let's Encrypt) | nginx PEM files: `cert.pem` / `key.pem` (`deploy/nginx.conf:34-35`) | `certbot renew && nginx -s reload` — **the .NET app never sees it** |
| **Token signing** | Sign OAuth/OIDC JWTs (id_token, access_token, logout_token, JARM) | **Self-signed by you**, once | Years (3-10) | PFX on disk: `Certificates.SigningPath` (`ServiceCollectionExtensions.cs:600`) | Deliberate overlap rotation (see below) — rare |
| **DP key protection** | Encrypt the Data Protection keyring XML at rest | **Reuses the signing PFX** | Same as signing | Same PFX (`ServiceCollectionExtensions.cs:175`) | Same as signing |

**Why Let's Encrypt cannot and should not issue the signing cert:**
- The signing cert is **not validated by any public CA**. Its public key is
  published at `/.well-known/jwks.json`; clients trust it because they point at
  *your* issuer URL, not because a CA vouched for it. A CA-issued cert would add
  zero trust and cost a TLS-challenge slot it was never designed for.
- Let's Encrypt issues **domain-validated TLS certs only**, 90-day, for servers
  that terminate TLS. A JWT signing cert has no domain — it is just a container
  for a crypto keypair.

**What actually happens during a Let's Encrypt renewal:**
```
certbot renew                    # swaps cert.pem + key.pem on disk
nginx -s reload                  # nginx re-reads, no connection drop
[STS .NET runs untouched]        # receives plain HTTP on :8080 as always
[Signing PFX untouched]          # keeps signing JWTs with the same key
[DP keyring untouched]           # still protected by the same signing PFX
```
TLS terminates at the reverse proxy **before** reaching the STS. The STS always
sees plain HTTP internally (per `docker-compose.yml`, port 8080). The 365-day
self-signed cert in `deploy/gen-cert.sh` is **dev-local only**; production puts a
real cert on the proxy and the STS is none the wiser.

**When the signing PFX does need rotation** (rare — suspected compromise or a
multi-year security policy): use **overlap**, not cold-swap:
1. Generate a new self-signed PFX (RSA or ECDSA P-256).
2. Register **both** with OpenIddict — `AddSigningCertificate(new)` +
   `AddSigningCertificate(old)`.
3. JWKS publishes both public keys.
4. New tokens sign with the new key; existing unexpired tokens still validate
   against the old key.
5. Wait out the max token TTL (access ~15 min, refresh configurable, ID ~5 min).
6. Remove the old key.

Zero downtime. Independent of the 90-day Let's Encrypt cycle.

**Where the vault fits in this picture:** the vault's optional `CertificateKeySource`
KEK backend (§4.5) uses the **signing PFX** (cert #2), never the TLS cert. If you
rotate the signing PFX via the overlap flow above, re-wrap the vault DEK under the
new PFX — a cheap operation (one call per DEK, no secret re-encryption, the sops
`updatekeys` pattern from §2.3). The vault's **default** KEK is the DP keyring
(cert #3's protection, indirectly), which has its own lifecycle independent of
both certs.

### 3.1 The convergent idea (all four converge on this)

```
┌─────────────────────────────────────────────────────────┐
│ KEK  (Master Key)   ← DP keyring / OS keychain / env     │
│   wraps ↓                                                │
│ Vault DEK           ← one per vault, CSPRNG 256-bit      │
│   wraps ↓                                                │
│ Item Key            ← one per secret, CSPRNG 256-bit     │
│   encrypts ↓                                             │
│ Ciphertext (AAD-bound, self-describing)                  │
└─────────────────────────────────────────────────────────┘
```

| Pattern | Borrowed from | Why |
|---------|---------------|-----|
| Envelope: KEK → DEK → item key | AWS KMS, Bitwarden | Limits KEK exposure; per-item keys enable granular rotation |
| **Self-describing ciphertext** `v1.<keyId>.<b64(iv‖ct‖tag)>` | Vault Transit | Rotation is free on reads; no side-table needed |
| **AEAD only** (AES-256-GCM / ChaCha20-Poly1305) | age, Vault, sops | Drop Bitwarden's legacy CBC+HMAC — AEAD is simpler and standard in .NET 10 |
| **AAD / encryption context** bound to ciphertext | AWS ESDK, sops MAC | Ties a secret to its scope; detects field-swap tampering |
| **Separate key-wrap from data-encrypt** | sops, age | Rotate master/KEK without re-encrypting every value |
| **Fail-fast header MAC** before decrypt | age | Tamper detection without key access |
| **`IProviderCredentialSink`-style abstraction** | sufficit-ai | Consumers never touch key material; swappable backends |
| **Token / AuthPayload / Settings tiers** | sufficit-ai | One entity, distinct sensitivity handling |

### 3.2 What we deliberately skip (scope discipline)

- ❌ **Client-side / zero-knowledge model** (Bitwarden's password-derived master key).
  We are a server-side STS, not an end-user password manager. The KEK comes from
  the host (DP keyring / env / KMS), not from a human password. Avoids Argon2
  tuning, brute-force surface, and "destructive key rotation" complexity.
- ❌ **OpenBao/Vault as a hard dependency.** Breaks zero-dependency onboarding.
  The vault module must work with just DP keyring (default) and *optionally*
  delegate to an external KMS/Transit when configured.
- ❌ **Dynamic secret generation** (DB creds with TTL, AWS IAM users). Out of
  scope for an STS; bring back as a separate plan if ever needed.
- ❌ **Multi-recipient / Shamir key sharing** (sops). Single KEK source is enough
  for v1; the abstraction leaves room for it later.
- ❌ **Convergent encryption.** Adds a footgun (offline plaintext-confirmation);
  no equality-search requirement justifies it.

## 4. Architecture

### 4.1 New project: `Sufficit.Identity.Vault`

```
src/vault/
├── Sufficit.Identity.Vault.csproj
├── ISecretStore.cs              ← read secrets by name (env / file / vault-backed)
├── IKeyVault.cs                 ← encrypt/decrypt as a service (Transit-style)
├── IVaultKeySource.cs           ← pluggable KEK provider (DP / cert / KMS)
├── Crypto/
│   ├── EnvelopeCrypto.cs        ← AES-256-GCM envelope (encrypt/decrypt/wrap)
│   ├── SelfDescribingCiphertext.cs  ← "v1.<keyId>.<b64(iv‖ct‖tag||aad-hash)>"
│   └── KeyId.cs                 ← key version + name parsing
├── Keys/
│   ├── DataProtectionKeySource.cs   ← default: wrap DEK with DP keyring
│   ├── CertificateKeySource.cs      ← alt: wrap DEK with signing cert RSA
│   └── ExternalKmsKeySource.cs      ← alt (stub): AWS KMS / Azure KV / Transit
├── Stores/
│   ├── EnvironmentSecretStore.cs    ← default ISecretStore: env vars + files
│   └── EncryptedFieldStore.cs       ← at-rest field encryption for DB columns
├── VaultOptions.cs
└── ServiceCollectionExtensions.cs
```

### 4.2 Core interfaces

```csharp
/// <summary>Transit-style encryption-as-a-service. Keys never leave the vault.</summary>
public interface IKeyVault
{
    /// <summary>Encrypts plaintext under a named, versioned key. Returns self-describing ciphertext.</summary>
    Task<string> EncryptAsync(string keyName, ReadOnlySpan<byte> plaintext,
        IReadOnlyDictionary<string, string>? additionalAuthenticatedData = null,
        CancellationToken ct = default);

    /// <summary>Decrypts self-describing ciphertext. The embedded key id selects the key version.</summary>
    Task<ReadOnlyMemory<byte>> DecryptAsync(string ciphertext,
        IReadOnlyDictionary<string, string>? additionalAuthenticatedData = null,
        CancellationToken ct = default);

    /// <summary>Creates a new key version for <paramref name="keyName"/>. New encrypts use it; old versions still decrypt.</summary>
    Task<KeyId> RotateKeyAsync(string keyName, CancellationToken ct = default);
}

/// <summary>Reads named secrets from a pluggable source. Consumers never touch the source.</summary>
public interface ISecretStore
{
    Task<string?> GetSecretAsync(string name, CancellationToken ct = default);
}

/// <summary>Provides the KEK that wraps per-vault DEKs. Default = DP keyring.</summary>
public interface IVaultKeySource
{
    Task<ReadOnlyMemory<byte>> UnwrapAsync(ReadOnlyMemory<byte> wrappedDek, CancellationToken ct = default);
    Task<ReadOnlyMemory<byte>> WrapAsync(ReadOnlyMemory<byte> dek, CancellationToken ct = default);
}
```

### 4.3 Ciphertext format (self-describing, age/Vault-inspired)

```
s1.<keyName>:<keyVersion>.<base64url(iv ‖ ciphertext ‖ tag)>.<base64url(aadHash)>
│   │         │            │                                                │
│   │         │            └── AES-256-GCM payload (12-byte iv, ct, 16-byte tag)
│   │         └── integer, monotonically increasing per keyName
│   └── stable string, e.g. "ssf-stream-authz", "dpop-nonce"
└── format schema version (increment only on breaking format change)
```

- **No side table needed** — the key name and version are embedded, so decrypt
  picks the right key from the DEK that wraps that key version.
- **`aadHash`** = first 8 bytes of HMAC-SHA256(aad, dek). Lets us fail-fast on
  AAD mismatch / field-swap without exposing the AAD itself. (sops MAC pattern.)
- Parsed by `SelfDescribingCiphertext.Parse(string)` → `(schemaVersion, keyName,
  keyVersion, iv, ct, tag, aadHash)`.

### 4.4 Key hierarchy and persistence

```
KEK (from IVaultKeySource — DP keyring by default)
  │
  ├── wraps Vault DEK #1  (256-bit, persisted wrapped in `vault_keys` table)
  │     ├── wraps ItemKey "ssf-stream-authz" v2   (in-memory, lazy-unwrapped)
  │     │     └── encrypts SsfStream.Authorization ciphertext blobs
  │     └── wraps ItemKey "dpop-nonce" v1
  │           └── encrypts DPoP nonce cache entries
  │
  └── wraps Vault DEK #2  (rotated; old secrets still decrypt via #1)
```

- **One DEK per "vault scope"** (default scope = the whole app). The DEK is
  wrapped by the KEK and persisted in a `vault_keys` table (`key_name`,
  `key_version`, `wrapped_dek`, `created_at_utc`, `retired_at_utc`).
- **Item keys** are derived/wrapped per `keyName` and cached in-memory
  (`ConcurrentDictionary<KeyId, byte[]>`) after unwrap. Never persisted unwrapped.
- **Rotation:** `RotateKeyAsync` creates a new key version + new wrapped item key
  under the DEK. Old ciphertext keeps decrypting (version embedded). New encrypts
  use the latest version. No bulk re-encryption needed for reads.

### 4.5 Backends (pluggable, opt-in)

| Backend | Use when | KEK source |
|---------|----------|------------|
| **DP keyring** (default) | Dev, single-host prod | ASP.NET Core Data Protection (already configured at `ServiceCollectionExtensions.cs:164`) |
| **Signing certificate** | Prod with PFX on disk | RSA-OAEP wrap with the existing **signing** PFX (cert #2 in §3.0 — *not* the TLS cert) |
| **External KMS** (stub in v1) | Cloud prod | AWS KMS `GenerateDataKey` / Azure KV `WrapKey` / Vault Transit — implements `IVaultKeySource`, configured by `VaultOptions.KeySource = "aws-kms"` etc. |

The default (DP keyring) keeps **zero new dependencies**. The cert backend
reuses the **signing** PFX that prod already loads (cert #2, §3.0 — has nothing to
do with the 90-day TLS/Let's Encrypt cert, which lives on the proxy). If the
signing PFX is rotated (rare, §3.0 overlap flow), re-wrap the vault DEK under the
new PFX — cheap, no secret re-encryption. The external-KMS backend is a thin
`IVaultKeySource` impl documented in the runbook but not wired by default.

## 5. Integration into sufficit-identity (consumers)

### 5.1 Phase 1 — At-rest field encryption (closes the plaintext gaps)

| Consumer | Secret field | Today | After |
|----------|--------------|-------|-------|
| `SsfStreamStore` | `SsfStream.Authorization` | plaintext column | ciphertext via `IKeyVault.EncryptAsync("ssf-stream-authz", …)` |
| `DistributedDpopNonceStore` | nonce value | plaintext cache entry | ciphertext |
| `DistributedCibaPendingRequestStore` | pending request JSON | plaintext cache entry | ciphertext |
| `ClientManagementService` | client secret on create/update | hashed (good) + plaintext echo (bad) | ciphertext for the "show once" echo, hashed for verify |

Each consumer takes `IKeyVault` via DI and calls `EncryptAsync`/`DecryptAsync`
with an AAD dict binding the secret to its owner (e.g.
`{ "stream_id": streamId }` for SSF auth tokens). This is the sops MAC pattern —
a ciphertext lifted from stream A won't decrypt for stream B.

### 5.2 Phase 2 — `ISecretStore` for config-time secrets

Today `Program.cs:21` relies on `WebApplication.CreateBuilder` defaults (user
secrets in dev, env vars always). Phase 2 introduces `ISecretStore` so consumers
can ask for a secret by name without knowing the source:

```csharp
// before
var dbPassword = _config["ConnectionStrings:DefaultConnection"]; // env-coupled

// after
var dbPassword = await _secretStore.GetSecretAsync("database/password");
```

- **Default impl `EnvironmentSecretStore`** reads `SUFFICIT_SECRET_<NAME>` env
  vars and falls back to `IConfiguration`. Zero-behavior-change default.
- **Optional `VaultBackedSecretStore`** reads from the encrypted `vault_secrets`
  table (a named-secret store like Vault KV) for operators who want secrets in
  the DB rather than env vars. Opt-in via `VaultOptions.EnableSecretStore = true`.

### 5.3 Phase 3 — Sign/verify as a service (optional, Transit for JWTs)

The biggest production win: **move token-signing key material out of the PFX-on-disk
model** into `IKeyVault.SignAsync` / `VerifyAsync`. The signing private key never
leaves the vault; the STS asks the vault to sign a JWT digest.

- Adds `SignAsync(keyName, payload)` / `VerifyAsync(keyName, signature, payload)`
  to `IKeyVault`, backed by an RSA/ECDSA key held inside the vault.
- OpenIddict's certificate credential is replaced at token generation by a
  custom IdentityModel `ICryptoProvider`/`SecurityKey` that delegates to the
  vault. The JWKS event publishes the retained public JWK versions. This is the
  "Transit for JWTs" pattern.
- **Scope caution:** this is the most invasive change and touches the JWKS
  endpoint. Phase 3 is opt-in (`VaultOptions.ManageSigningKeys = true`) and the
  PFX path remains the default so onboarding isn't broken.

## 6. Data model

Two new tables, one migration.

### 6.1 `vault_keys` — wrapped DEKs / item keys

| Column | Type | Notes |
|--------|------|-------|
| `id` | bigint PK | autoincrement |
| `key_name` | varchar(64) | e.g. `ssf-stream-authz`, indexed with version |
| `key_version` | int | monotonic per name |
| `purpose` | varchar(16) | `symmetric` \| `signing` |
| `wrapped_key` | longblob | DEK-wrapped or KEK-wrapped blob |
| `public_jwk` | json null | for signing keys (so JWKS can publish) |
| `created_at_utc` | datetime(6) | |
| `retired_at_utc` | datetime(6) null | null = active or still-decryptable |
| Unique | `(key_name, key_version)` | |

### 6.2 `vault_secrets` — named secrets (KV-style, opt-in Phase 2)

| Column | Type | Notes |
|--------|------|-------|
| `id` | bigint PK | |
| `name` | varchar(128) | unique, e.g. `database/password` |
| `ciphertext` | longtext | self-describing blob |
| `aad` | json null | bound context |
| `updated_at_utc` | datetime(6) | |
| `updated_by` | varchar(128) | operator subject |

### 6.3 Migration

`AddVaultTables` via `dotnet ef migrations add`. Update
`IdentityDatabaseSchema.cs` (`VaultKeysMigrationId`),
`DatabaseSchemaContractTests.cs`, `MariaDbMigrationIntegrationTests.cs`, and
regenerate `docs/migration/sql/001-create-empty-database.sql` (there is a test
that diffs this).

## 7. Configuration (`VaultOptions`)

```csharp
public sealed class VaultOptions
{
    public const string SectionName = "Sufficit:Vault";

    /// <summary>Master toggle. When false, IKeyVault resolves to a pass-through
    /// (no-op) impl so consumers can be wired unconditionally without forcing
    /// encryption on in dev.</summary>
    public bool Enabled { get; init; } = false;

    /// <summary>KEK source: "dataprotection" (default) | "certificate" | "aws-kms" | "azure-kv".</summary>
    public string KeySource { get; init; } = "dataprotection";

    /// <summary>DP protector purpose used as the KEK. Changing this invalidates all wrapped DEKs.</summary>
    public string DataProtectionPurpose { get; init; } = "Sufficit.Identity.Vault.Master.v1";

    /// <summary>Opt-in: store named secrets in the vault_secrets table (Phase 2).</summary>
    public bool EnableSecretStore { get; init; } = false;

    /// <summary>Opt-in: vault manages JWT signing keys instead of PFX-on-disk (Phase 3).</summary>
    public bool ManageSigningKeys { get; init; } = false;

    /// <summary>Name of the versioned OpenIddict signing key.</summary>
    public string SigningKeyName { get; init; } = "oidc-signing";

    /// <summary>External KMS settings (only used when KeySource != dataprotection).</summary>
    public ExternalKmsOptions? ExternalKms { get; init; }
}
```

- **`Enabled = false` default** = zero behavior change. Consumers inject
  `IKeyVault` and get a `PassThroughKeyVault` (encrypt = return plaintext as-is
  with a marker prefix; decrypt = strip it). This lets us wire the plumbing in
  Phase 1 without forcing every dev to enable it.
- **`Enabled = true`** = real envelope crypto with the configured `KeySource`.

## 8. Phased delivery

Each phase is independently shippable and leaves CI green.

### Phase 1 — Core vault module + at-rest field encryption (implemented)
1. New `src/vault/Sufficit.Identity.Vault.csproj` + interfaces + `EnvelopeCrypto`
   (AES-256-GCM) + `SelfDescribingCiphertext` + `DataProtectionKeySource`.
2. `vault_keys` table + migration + schema contract test updates + SQL regen.
3. Wire `IKeyVault` in `ServiceCollectionExtensions`; `PassThroughKeyVault`
   when `Enabled = false`.
4. Consumers: `SsfStreamStore` (SSF auth token), `DistributedDpopNonceStore`,
   `DistributedCibaPendingRequestStore` — call `EncryptAsync`/`DecryptAsync`
   with owner-bound AAD.
5. Tests: envelope round-trip, AAD mismatch rejection, key rotation (old
   ciphertext still decrypts), `PassThroughKeyVault` no-op contract and
   encrypted distributed-store payloads.

The remaining named-secret CRUD (`vault_secrets`) and signing-key management
are now available. Until `ManageSigningKeys` is explicitly enabled, JWT
signing continues through the existing OpenIddict certificate path.

### Phase 2 — `ISecretStore` + named-secret KV table (implemented)
1. `ISecretStore` + `EnvironmentSecretStore` (default) + `VaultBackedSecretStore`
   (opt-in) + `vault_secrets` table + migration.
2. Management API endpoint `GET/PUT/DELETE /api/vault/secrets/{name}`
   (capability-scoped; values are write-only in the response).
3. Config-time consumers still require a separate rollout; existing
   connection/certificate settings remain configuration-bound until their
   secret rotation contract is approved.
4. Store round-trip and environment fallback tests are included; full
   management authorization integration remains a deployment-test gate.

### Phase 3 — Signing-key management (Transit for JWTs, opt-in; implemented)
1. `SignAsync` / `VerifyAsync` on `IKeyVault`; versioned RSA keys with
   `public_jwk` in `vault_keys`.
2. Custom OpenIddict signing credential provider and JWKS publication are
   enabled by `ManageSigningKeys`; the certificate path remains the default.
3. RSA signing, delegated IdentityModel provider, JWKS and overlapping-key
   rotation have unit and HTTP integration coverage.

## 9. Security properties & threat model

| Property | How achieved |
|----------|-------------|
| **Plaintext-at-rest eliminated** for covered fields | All stored blobs are self-describing ciphertext (Phase 1) |
| **Key material isolation** | Item keys never leave the vault; consumers only see ciphertext |
| **Tamper detection** | GCM tag + AAD-hash mismatch fails fast (age/sops pattern) |
| **Field-swap resistance** | AAD binds ciphertext to owner (`stream_id`, `jti`, …) |
| **Cheap rotation** | New key version; old ciphertext decrypts via embedded version |
| **Master-key rotation without re-encrypt** | Re-wrap DEK under new KEK (sops `updatekeys` pattern) |
| **Fail-closed** | `Enabled = true` + missing KEK → startup throw (matches existing cert posture at `ServiceCollectionExtensions.cs:616`) |
| **Zero new hard deps** | Default backend = DP keyring (already in use); `System.Security.Cryptography` AEAD is BCL |
| **Defense in depth** | Vault doesn't replace DP, mTLS, or breached-password checks — it adds at-rest confidentiality |

**Not in scope / not claimed:**
- Does not protect against an attacker who compromises the running process
  (keys are in memory). Same trust boundary as DP today.
- Does not replace HSM-backed KMS; the external-KMS backend is a stub for
  operators who already have one.
- Does not do client-side encryption (we are a server, not a password manager).

## 10. Testing strategy

- **Unit:** `EnvelopeCrypto` round-trips, AAD mismatch, nonce reuse resistance
  (GCM), key-version selection from ciphertext prefix.
- **Contract:** `IKeyVault` implementations (pass-through, DP, cert) satisfy the
  same round-trip + rotation contract via a shared `[Theory]`.
- **Integration:** `WebApplicationFactory` test that stores an SSF stream with an
  auth token, confirms the DB column holds ciphertext (not the bearer token), and
  the store can still deliver the SET.
- **Migration:** `MariaDbMigrationIntegrationTests` includes `vault_keys` +
  `vault_secrets`; `DatabaseSchemaContractTests` asserts the new migration id.

## 11. Documentation & ONBOARD updates

- New `docs/runbooks/RUNBOOK-VAULT.md`: enable, choose `KeySource`, rotate keys,
  migrate plaintext columns (re-encrypt script), troubleshoot.
- `ONBOARD.md` — add a "Secrets at rest" section: default (off) → flip
  `Sufficit:Vault:Enabled=true` → covered fields auto-encrypt.
- `docs/plans/PLAN-VAULT.md` (this file) moved to `docs/activities/` on completion
  per the timestamp convention.

## 12. Out of scope (explicit non-goals)

- OpenBao/Vault as a dependency or bundled service.
- Client-side / password-derived master key (Bitwarden model).
- Dynamic secret generation (DB/AWS creds with TTL).
- Multi-recipient / Shamir key sharing.
- Convergent / deterministic encryption.
- Replacing the existing DP keyring (vault sits *on top of* it as the KEK).
- Migrating sufficit-ai to this vault (separate plan; the module is shareable
  because it's a standalone library project).

## 13. Open questions (to resolve before Phase 1 build)

1. **Key cache eviction:** in-memory item-key cache — unbounded, or LRU with a
   cap? Default suggestion: unbounded (keys are small, count is low) with a
   `FlushAsync` for tests/admin.
2. **AAD for cache-backed stores** (DPoP nonce, CIBA): the cache key is already
   the lookup id; do we add AAD at all, or rely on the cache backend's isolation?
   Suggestion: AAD = `{ "scope": "dpop-nonce" }` (constant per store) to at least
   bind the ciphertext to its purpose.
3. **Re-encrypt-on-read vs lazy:** when a key rotates, do we re-encrypt old
   ciphertext on next read (write-amplification) or leave it on the old version?
   Suggestion: leave on old version (free rotation); provide an admin
   `ReEncryptAllAsync(keyName)` for deliberate re-key.
4. **Should the management UI expose vault admin?** (view keys, rotate, view
   named secrets). Probably yes for Phase 2 but out of Phase 1 scope.
