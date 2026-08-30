using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Tests.Infrastructure;
using Sufficit.Identity.Management.Provisioning;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Vault;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Email;
using Sufficit.Identity.STS.Vault;
using Sufficit.Identity.Vault;
using Sufficit.Identity.Vault.Crypto;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class VaultTests
{
    [Fact]
    public void Envelope_round_trips_plaintext()
    {
        var key = EnvelopeCrypto.GenerateKey();
        var plaintext = "Bearer my-secret-token"u8.ToArray();
        var aad = "owner=stream-1"u8.ToArray();

        var ciphertext = EnvelopeCrypto.Encrypt(plaintext, key, aad);
        var decrypted = EnvelopeCrypto.Decrypt(ciphertext, key, aad);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Envelope_rejects_tampered_ciphertext()
    {
        var key = EnvelopeCrypto.GenerateKey();
        var plaintext = "secret"u8.ToArray();
        var ciphertext = EnvelopeCrypto.Encrypt(plaintext, key, []);

        // Flip a byte in the ciphertext (tamper).
        ciphertext[^1] ^= 0xFF;

        Assert.ThrowsAny<CryptographicException>(
            () => EnvelopeCrypto.Decrypt(ciphertext, key, []));
    }

    [Fact]
    public void Envelope_rejects_aad_mismatch()
    {
        var key = EnvelopeCrypto.GenerateKey();
        var plaintext = "secret"u8.ToArray();
        var ciphertext = EnvelopeCrypto.Encrypt(plaintext, key, "owner=A"u8.ToArray());

        Assert.ThrowsAny<CryptographicException>(
            () => EnvelopeCrypto.Decrypt(ciphertext, key, "owner=B"u8.ToArray()));
    }

    [Fact]
    public async Task Pass_through_round_trips_without_crypto()
    {
        IKeyVault vault = new PassThroughKeyVault();
        const string plaintext = "Bearer plaintext-token";

        var ciphertext = await vault.EncryptAsync("test-key", plaintext);
        var decrypted = await vault.DecryptStringAsync(ciphertext);

        Assert.Equal(plaintext, decrypted);
        // The ciphertext must NOT equal the plaintext (it's marker-prefixed).
        Assert.NotEqual(plaintext, ciphertext);
    }

    [Fact]
    public async Task Real_vault_round_trips_and_persists_keys()
    {
        var (vault, _) = CreateRealVault();
        const string plaintext = "Bearer my-push-token";

        var ciphertext = await vault.EncryptAsync(
            "ssf-stream-authz",
            System.Text.Encoding.UTF8.GetBytes(plaintext),
            new Dictionary<string, string> { ["stream_id"] = "s1" });
        var decrypted = await vault.DecryptStringAsync(
            ciphertext,
            new Dictionary<string, string> { ["stream_id"] = "s1" });

        Assert.Equal(plaintext, decrypted);
        // Ciphertext must not contain the plaintext.
        Assert.DoesNotContain(plaintext, ciphertext);
    }

    [Fact]
    public async Task Real_vault_reads_legacy_pass_through_values_during_migration()
    {
        IKeyVault compatibility = new PassThroughKeyVault();
        var legacy = await compatibility.EncryptAsync(
            "ssf-stream-authz",
            "Bearer legacy-token");
        // F-2 (eval 2026-08-14): reading pt1 values through the real vault
        // now requires the bounded compatibility window; by default the
        // marker is rejected (see VaultPlaintextCompatibilityTests).
        var (vault, _) = CreateRealVault(
            allowPlaintextRead: true,
            plaintextReadDeadline: DateTimeOffset.UtcNow.AddDays(1));

        var decrypted = await vault.DecryptStringAsync(
            legacy,
            new Dictionary<string, string> { ["stream_id"] = "legacy" });

        Assert.Equal("Bearer legacy-token", decrypted);
        var replacement = await vault.EncryptAsync(
            "ssf-stream-authz",
            "Bearer legacy-token",
            new Dictionary<string, string> { ["stream_id"] = "legacy" });
        Assert.StartsWith("v1.", replacement, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Real_vault_rejects_wrong_aad()
    {
        var (vault, _) = CreateRealVault();
        const string plaintext = "secret";

        var ciphertext = await vault.EncryptAsync(
            "test-key",
            System.Text.Encoding.UTF8.GetBytes(plaintext),
            new Dictionary<string, string> { ["stream_id"] = "s1" });

        await Assert.ThrowsAnyAsync<CryptographicException>(
            () => vault.DecryptStringAsync(
                ciphertext,
                new Dictionary<string, string> { ["stream_id"] = "s2" }));
    }

    [Fact]
    public async Task Real_vault_rejects_aad_hash_with_different_length()
    {
        var (vault, _) = CreateRealVault();
        var aad = new Dictionary<string, string> { ["stream_id"] = "s1" };
        var ciphertext = await vault.EncryptAsync("test-key", "secret", aad);
        var parts = ciphertext.Split('.', StringSplitOptions.None);
        parts[^1] = WebEncoders.Base64UrlEncode(new byte[7]);
        var malformed = string.Join('.', parts);

        await Assert.ThrowsAnyAsync<CryptographicException>(
            () => vault.DecryptStringAsync(malformed, aad));
    }

    [Fact]
    public async Task Real_vault_rejects_truncated_ciphertext()
    {
        var (vault, _) = CreateRealVault();
        var ciphertext = await vault.EncryptAsync("test-key", "secret");
        var parts = ciphertext.Split('.', StringSplitOptions.None);
        parts[2] = WebEncoders.Base64UrlEncode([1, 2, 3]);
        var malformed = string.Join('.', parts);

        await Assert.ThrowsAnyAsync<CryptographicException>(
            () => vault.DecryptStringAsync(malformed));
    }

    /// <summary>
    /// Regression (eval 2026-08-23, S-4): the key name and version inside a
    /// self-describing ciphertext are attacker-influenced input. A blob naming
    /// a SIGNING key must not reach that key's wrapped private material at
    /// all — the decrypt lookup is restricted to symmetric keys, so the two
    /// key spaces stay disjoint by construction instead of relying on the
    /// AES-GCM key-length check to reject the unwrapped signing key later.
    /// </summary>
    [Fact]
    public async Task Real_vault_refuses_to_decrypt_under_a_signing_key()
    {
        var (vault, _) = CreateRealVault();

        // Materialize a signing key, then point a real ciphertext at it.
        var signingKeys = await vault.GetSigningKeysAsync("oidc-signing");
        var signing = Assert.Single(signingKeys);

        var ciphertext = await vault.EncryptAsync("test-key", "secret");
        var parts = ciphertext.Split('.', StringSplitOptions.None);
        parts[1] = $"{signing.KeyName}:{signing.KeyVersion}";
        var confused = string.Join('.', parts);

        var error = await Assert.ThrowsAnyAsync<CryptographicException>(
            () => vault.DecryptStringAsync(confused));

        // "not found" proves the signing row was never a candidate, rather
        // than the unwrap succeeding and failing downstream on key length.
        Assert.Contains("not found", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Real_vault_old_ciphertext_decrypts_after_rotation()
    {
        var (vault, dbFactory) = CreateRealVault();
        const string plaintext = "Bearer rotate-me";

        var oldCiphertext = await vault.EncryptAsync("rot-key", plaintext);

        // Rotate — new encrypts use v2.
        await vault.RotateKeyAsync("rot-key");
        var newCiphertext = await vault.EncryptAsync("rot-key", plaintext);

        // Both old and new must decrypt.
        Assert.Equal(plaintext, await vault.DecryptStringAsync(oldCiphertext));
        Assert.Equal(plaintext, await vault.DecryptStringAsync(newCiphertext));

        // Two key versions persisted.
        await using var db = await dbFactory.CreateDbContextAsync();
        var versions = await db.VaultKeys
            .Where(k => k.KeyName == "rot-key")
            .ToListAsync();
        Assert.Equal(2, versions.Count);
    }
}
