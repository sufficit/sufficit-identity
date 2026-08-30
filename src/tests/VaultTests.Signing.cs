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
    public async Task Vault_signatures_verify_across_rotation_without_exposing_private_key()
    {
        var (vault, dbFactory) = CreateRealVault();
        var payload = System.Text.Encoding.UTF8.GetBytes("jwt-digest");

        var first = await vault.SignAsync("identity-signing", payload);
        Assert.StartsWith("sig1.identity-signing:1.", first,
            StringComparison.Ordinal);
        Assert.True(await vault.VerifyAsync(first, payload));
        Assert.False(await vault.VerifyAsync(first,
            System.Text.Encoding.UTF8.GetBytes("tampered")));

        await vault.RotateSigningKeyAsync("identity-signing");
        var second = await vault.SignAsync("identity-signing", payload);
        Assert.Contains(":2.", second, StringComparison.Ordinal);
        Assert.True(await vault.VerifyAsync(first, payload));
        Assert.True(await vault.VerifyAsync(second, payload));

        await using var database = await dbFactory.CreateDbContextAsync();
        var keys = await database.VaultKeys
            .Where(key => key.KeyName == "identity-signing")
            .ToArrayAsync();
        Assert.Equal(2, keys.Length);
        Assert.All(keys, key => Assert.Equal("signing", key.Purpose));
        Assert.All(keys, key => Assert.Contains("\"kty\":\"RSA\"",
            key.PublicJwk, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Signing_rotation_is_idempotent_and_only_the_active_key_can_issue()
    {
        var (vault, dbFactory) = CreateRealVault(new VaultOptions
        {
            Enabled = true,
            SigningKeyOverlapSeconds = 300,
        });
        var payload = System.Text.Encoding.UTF8.GetBytes("rotation-lifecycle");
        var oldSignature = await vault.SignAsync("lifecycle-signing", payload);

        var first = await vault.RotateSigningKeyAsync(
            "lifecycle-signing",
            "rotation-operation-1",
            "scheduled rotation");
        var retry = await vault.RotateSigningKeyAsync(
            "lifecycle-signing",
            "rotation-operation-1",
            "scheduled rotation");

        Assert.Equal(first, retry);
        Assert.Equal(2, first.Version);
        Assert.True(await vault.VerifyAsync(oldSignature, payload));
        await Assert.ThrowsAnyAsync<CryptographicException>(() =>
            vault.SignAsync("lifecycle-signing", 1, payload));

        var published = await vault.GetSigningKeysAsync("lifecycle-signing");
        Assert.Collection(
            published,
            active =>
            {
                Assert.Equal(2, active.KeyVersion);
                Assert.Equal(VaultSigningKeyStatus.Active, active.Status);
            },
            retiring =>
            {
                Assert.Equal(1, retiring.KeyVersion);
                Assert.Equal(VaultSigningKeyStatus.Retiring, retiring.Status);
                Assert.NotNull(retiring.RetireAfterUtc);
            });

        await using var database = await dbFactory.CreateDbContextAsync();
        Assert.Equal(2, await database.VaultKeys.CountAsync(key =>
            key.KeyName == "lifecycle-signing"));
        Assert.Equal(1, await database.VaultSigningKeyLifecycleOperations
            .CountAsync(item => item.Action == "rotate"));
    }

    [Fact]
    public async Task Elapsed_signing_key_is_retired_and_no_longer_verifies()
    {
        var clock = new MutableTimeProvider(
            new DateTimeOffset(2026, 8, 9, 12, 0, 0, TimeSpan.Zero));
        var (vault, dbFactory) = CreateRealVault(
            new VaultOptions
            {
                Enabled = true,
                SigningKeyOverlapSeconds = 60,
            },
            clock);
        var payload = System.Text.Encoding.UTF8.GetBytes("retirement");
        var oldSignature = await vault.SignAsync("retire-signing", payload);
        await vault.RotateSigningKeyAsync(
            "retire-signing",
            "rotation-before-retirement");

        clock.Advance(TimeSpan.FromSeconds(61));
        Assert.Single(await vault.GetSigningKeysAsync("retire-signing"));
        Assert.Equal(1, await vault.RetireSigningKeysAsync("retire-signing"));
        Assert.False(await vault.VerifyAsync(oldSignature, payload));

        await using var database = await dbFactory.CreateDbContextAsync();
        var retired = await database.VaultKeys.SingleAsync(key =>
            key.KeyName == "retire-signing" && key.KeyVersion == 1);
        Assert.Equal(VaultSigningKeyState.Retired, retired.SigningState);
        Assert.Equal(clock.GetUtcNow().UtcDateTime, retired.RetiredAtUtc);
        Assert.Contains(await database.VaultSigningKeyLifecycleOperations
                .ToArrayAsync(),
            item => item.Action == "retire" && item.KeyVersion == 1);
    }

    [Fact]
    public async Task Emergency_revocation_removes_jwks_and_blocks_live_tokens()
    {
        var (vault, dbFactory) = CreateRealVault();
        var payload = System.Text.Encoding.UTF8.GetBytes("emergency-revoke");
        var signature = await vault.SignAsync("revoked-signing", payload);

        Assert.True(await vault.RevokeSigningKeyAsync(
            "revoked-signing",
            1,
            "incident-2026-08-09",
            "private key exposure"));
        Assert.True(await vault.RevokeSigningKeyAsync(
            "revoked-signing",
            1,
            "incident-2026-08-09",
            "private key exposure"));

        Assert.Empty(await vault.GetSigningKeysAsync("revoked-signing"));
        Assert.False(await vault.VerifyAsync(signature, payload));
        await Assert.ThrowsAnyAsync<CryptographicException>(() =>
            vault.SignAsync("revoked-signing", payload));

        await using var database = await dbFactory.CreateDbContextAsync();
        var key = await database.VaultKeys.SingleAsync(item =>
            item.KeyName == "revoked-signing");
        Assert.Equal(VaultSigningKeyState.Revoked, key.SigningState);
        Assert.NotNull(key.RevokedAtUtc);
        Assert.Equal(1, await database.VaultSigningKeyLifecycleOperations
            .CountAsync(item => item.Action == "revoke"));
    }

    [Fact]
    public async Task Rotation_lease_recovers_after_expiry_without_two_active_keys()
    {
        var clock = new MutableTimeProvider(
            new DateTimeOffset(2026, 8, 9, 12, 0, 0, TimeSpan.Zero));
        var options = new VaultOptions
        {
            Enabled = true,
            SigningKeyOverlapSeconds = 60,
            SigningKeyLockSeconds = 5,
        };
        var (vault, dbFactory) = CreateRealVault(options, clock);
        await vault.GetSigningKeysAsync("lease-signing");
        await using (var database = await dbFactory.CreateDbContextAsync())
        {
            database.VaultSigningKeyLocks.Add(new VaultSigningKeyLock
            {
                KeyName = "lease-signing",
                OwnerId = "other-replica",
                ExpiresAtUtc = clock.GetUtcNow().UtcDateTime.AddSeconds(5),
            });
            await database.SaveChangesAsync();
        }

        await Assert.ThrowsAsync<
                Sufficit.Identity.Vault.KeyOperationLeaseConflictException>(() =>
            vault.RotateSigningKeyAsync("lease-signing", "lease-conflict"));
        clock.Advance(TimeSpan.FromSeconds(6));
        var rotated = await vault.RotateSigningKeyAsync(
            "lease-signing",
            "lease-recovered");
        Assert.Equal(2, rotated.Version);

        await using var verification = await dbFactory.CreateDbContextAsync();
        Assert.Equal(1, await verification.VaultKeys.CountAsync(key =>
            key.KeyName == "lease-signing"
            && key.SigningState == VaultSigningKeyState.Active));
    }

    [Fact]
    public async Task Concurrent_rotation_requests_never_leave_multiple_active_keys()
    {
        var databasePath = Path.Combine(
            Path.GetTempPath(),
            $"vault-concurrency-{Guid.NewGuid():N}.db");
        ServiceProvider? provider = null;
        try
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddDataProtection().UseEphemeralDataProtectionProvider();
            services.AddDbContextFactory<AppDbContext>(database =>
            {
                database.UseSqlite($"Data Source={databasePath}");
                database.UseOpenIddict();
            });
            provider = services.BuildServiceProvider();
            var factory = provider.GetRequiredService<
                IDbContextFactory<AppDbContext>>();
            await using (var setup = await factory.CreateDbContextAsync())
            {
                await setup.Database.EnsureCreatedAsync();
            }
            var options = new VaultOptions
            {
                Enabled = true,
                SigningKeyOverlapSeconds = 60,
                SigningKeyLockSeconds = 60,
            };
            var keySource = new DataProtectionKeySource(
                provider.GetRequiredService<IDataProtectionProvider>(),
                options);
            var logger = provider.GetRequiredService<ILogger<KeyVault>>();
            IKeyVault firstReplica = new KeyVault(
                factory, keySource, logger, options);
            IKeyVault secondReplica = new KeyVault(
                factory, keySource, logger, options);
            await firstReplica.GetSigningKeysAsync("concurrent-signing");

            static async Task<bool> RotateAsync(
                IKeyVault vault,
                string operationId)
            {
                try
                {
                    await vault.RotateSigningKeyAsync(
                        "concurrent-signing",
                        operationId);
                    return true;
                }
                catch (InvalidOperationException)
                {
                    return false;
                }
            }

            var results = await Task.WhenAll(
                RotateAsync(firstReplica, "concurrent-rotation-1"),
                RotateAsync(secondReplica, "concurrent-rotation-2"));
            Assert.Contains(true, results);

            await using var verification = await factory.CreateDbContextAsync();
            Assert.Equal(1, await verification.VaultKeys.CountAsync(key =>
                key.KeyName == "concurrent-signing"
                && key.SigningState == VaultSigningKeyState.Active));
            Assert.Equal(
                1 + results.Count(result => result),
                await verification.VaultKeys.CountAsync(key =>
                    key.KeyName == "concurrent-signing"));
        }
        finally
        {
            if (provider is not null) await provider.DisposeAsync();
            if (File.Exists(databasePath)) File.Delete(databasePath);
        }
    }

    [Fact]
    public async Task Kek_failure_rolls_back_rotation_and_preserves_the_active_key()
    {
        FailingKeySource? failing = null;
        var (vault, dbFactory) = CreateRealVault(
            new VaultOptions
            {
                Enabled = true,
                SigningKeyOverlapSeconds = 60,
            },
            keySourceFactory: provider => failing = new FailingKeySource(
                new DataProtectionKeySource(provider, new VaultOptions())));
        await vault.GetSigningKeysAsync("rollback-signing");
        failing!.FailWrap = true;

        await Assert.ThrowsAnyAsync<CryptographicException>(() =>
            vault.RotateSigningKeyAsync(
                "rollback-signing",
                "failed-rotation"));

        await using var database = await dbFactory.CreateDbContextAsync();
        var onlyKey = Assert.Single(await database.VaultKeys
            .Where(key => key.KeyName == "rollback-signing")
            .ToArrayAsync());
        Assert.Equal(VaultSigningKeyState.Active, onlyKey.SigningState);
        Assert.DoesNotContain(await database.VaultSigningKeyLifecycleOperations
                .ToArrayAsync(),
            item => item.OperationId == "failed-rotation");
    }

    [Fact]
    public async Task Dedicated_certificate_kek_round_trips_and_passes_readiness()
    {
        var directory = Directory.CreateTempSubdirectory("vault-kek-");
        try
        {
            const string password = "test-only-password";
            using var rsa = RSA.Create(3072);
            var request = new CertificateRequest(
                "CN=vault-kek.tests.local",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            using var certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddDays(30));
            var path = Path.Combine(directory.FullName, "vault-kek.pfx");
            await File.WriteAllBytesAsync(
                path,
                certificate.Export(X509ContentType.Pfx, password));
            using var source = new CertificateKeySource(new VaultOptions
            {
                CertificatePath = path,
                CertificatePassword = password,
            });
            var plaintext = RandomNumberGenerator.GetBytes(32);
            var wrapped = source.Wrap(plaintext);

            Assert.Equal(plaintext, source.Unwrap(wrapped));
            var readiness = new VaultKekReadinessService(
                source,
                Microsoft.Extensions.Logging.Abstractions
                    .NullLogger<VaultKekReadinessService>.Instance);
            await readiness.StartAsync(CancellationToken.None);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task IdentityModel_provider_delegates_signing_to_vault_and_uses_public_rotation_keys()
    {
        var (vault, _) = CreateRealVault();
        var payload = System.Text.Encoding.UTF8.GetBytes("identity-model-signature");
        var descriptor = (await vault.GetSigningKeysAsync("oidc-signing")).Single();
        var key = new VaultSigningSecurityKey(descriptor, vault);

        using var signer = key.CryptoProviderFactory.CreateForSigning(
            key,
            SecurityAlgorithms.RsaSha256);
        var signature = signer.Sign(payload);

        Assert.True(signer.Verify(payload, signature));
        Assert.Equal(descriptor.KeyId, key.KeyId);
        Assert.DoesNotContain("PRIVATE", key.PublicJwk,
            StringComparison.OrdinalIgnoreCase);

        await vault.RotateSigningKeyAsync("oidc-signing");
        var rotated = await vault.GetSigningKeysAsync("oidc-signing");
        Assert.Equal(2, rotated.Count);
        Assert.Contains(rotated, item => item.KeyVersion == descriptor.KeyVersion);
    }

    [Fact]
    public async Task Vault_managed_signing_publishes_versioned_jwks_endpoint()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                [$"{VaultOptions.SectionName}:Enabled"] = "true",
                [$"{VaultOptions.SectionName}:ManageSigningKeys"] = "true",
                ["Sufficit:Identity:Tokens:UseReferenceAccessTokens"] = "false",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();

        using var response = await client.GetAsync(
            "/.well-known/openid-configuration/jwks");
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadAsStringAsync();

        Assert.Contains("vault:oidc-signing:1", body,
            StringComparison.Ordinal);
        Assert.Contains("\"kty\":\"RSA\"", body,
            StringComparison.Ordinal);

        await factory.Services.GetRequiredService<IKeyVault>()
            .RotateSigningKeyAsync("oidc-signing");
        using var rotatedResponse = await client.GetAsync(
            "/.well-known/openid-configuration/jwks");
        rotatedResponse.EnsureSuccessStatusCode();
        var rotatedBody = await rotatedResponse.Content.ReadAsStringAsync();
        Assert.Contains("vault:oidc-signing:1", rotatedBody,
            StringComparison.Ordinal);
        Assert.Contains("vault:oidc-signing:2", rotatedBody,
            StringComparison.Ordinal);

    }
}
