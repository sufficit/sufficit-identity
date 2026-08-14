using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Vault;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// F-7 (eval 2026-08-14): symmetric DEK first-use creation and rotation must
/// run under the per-key-name distributed operation lease. Concurrent
/// replicas racing maxVersion+1 would otherwise collide on the
/// (KeyName, KeyVersion) unique index with an opaque DbUpdateException. The
/// lease semantics are exercised deterministically by pre-inserting lease
/// rows that simulate another replica.
/// </summary>
public sealed class VaultSymmetricKeyLeaseTests
{
    [Fact]
    public async Task Rotation_is_rejected_while_another_replica_holds_the_lease()
    {
        using var harness = VaultLeaseHarness.Create();
        harness.SeedKey("leased-key", version: 1);
        harness.HoldLease("leased-key", expiresIn: TimeSpan.FromMinutes(5));

        var exception = await Assert.ThrowsAsync<
                Sufficit.Identity.Vault.KeyOperationLeaseConflictException>(() =>
            harness.Vault.RotateKeyAsync("leased-key"));

        Assert.Contains("another replica", exception.Message, StringComparison.Ordinal);
        // The foreign lease must not be stolen or released by the loser.
        Assert.NotNull(harness.GetLease("leased-key"));
    }

    [Fact]
    public async Task Abandoned_expired_lease_is_recovered_and_rotation_succeeds()
    {
        using var harness = VaultLeaseHarness.Create();
        harness.SeedKey("stale-key", version: 1);
        // A lease left behind by a crashed replica: already expired.
        harness.HoldLease("stale-key", expiresIn: TimeSpan.FromSeconds(-1));

        var rotated = await harness.Vault.RotateKeyAsync("stale-key");

        Assert.Equal(("stale-key", 2), (rotated.Name, rotated.Version));
        // The recovered lease is released on dispose.
        Assert.Null(harness.GetLease("stale-key"));
    }

    [Fact]
    public async Task Cold_key_creation_reuses_v1_created_by_the_lease_holder()
    {
        // Replica A holds the lease and has just created v1; replica B's
        // first-use path must absorb the race via its bounded re-read
        // instead of failing the encrypt.
        using var harness = VaultLeaseHarness.Create();
        harness.SeedKey("raced-key", version: 1);
        harness.HoldLease("raced-key", expiresIn: TimeSpan.FromMinutes(5));

        var ciphertext = await harness.Vault.EncryptAsync(
            "raced-key",
            "payload"u8.ToArray());

        Assert.StartsWith("v1.raced-key:1.", ciphertext, StringComparison.Ordinal);
        var plaintext = await harness.Vault.DecryptAsync(ciphertext);
        Assert.Equal("payload"u8.ToArray(), plaintext.ToArray());
    }

    [Fact]
    public async Task Concurrent_cold_start_on_a_shared_database_yields_one_key()
    {
        // Two vault instances over one database hitting a cold key name at
        // the same time: every encrypt must succeed and exactly one v1 row
        // may exist afterwards, regardless of which replica won the lease.
        using var harness = VaultLeaseHarness.Create();
        var second = harness.CreatePeerVault();

        var tasks = Task.WhenAll(
            Task.Run(() => harness.Vault.EncryptAsync(
                "shared-cold-key", "one"u8.ToArray())),
            Task.Run(() => second.EncryptAsync(
                "shared-cold-key", "two"u8.ToArray())));

        var ciphertexts = await tasks;
        foreach (var ciphertext in ciphertexts)
        {
            Assert.StartsWith("v1.shared-cold-key:1.", ciphertext,
                StringComparison.Ordinal);
        }

        await using var db = await harness.CreateDbContextAsync();
        var versions = await db.VaultKeys
            .Where(k => k.KeyName == "shared-cold-key" && k.Purpose == "symmetric")
            .Select(k => k.KeyVersion)
            .ToListAsync();
        Assert.Equal([1], versions);
    }

    private sealed class VaultLeaseHarness : IDisposable
    {
        private readonly ServiceProvider _provider;
        private readonly Microsoft.Data.Sqlite.SqliteConnection _connection;
        private readonly DataProtectionKeySource _kek;

        private VaultLeaseHarness(
            ServiceProvider provider,
            Microsoft.Data.Sqlite.SqliteConnection connection,
            KeyVault vault,
            DataProtectionKeySource kek)
        {
            _provider = provider;
            _connection = connection;
            _kek = kek;
            Vault = vault;
        }

        public KeyVault Vault { get; }

        public static VaultLeaseHarness Create()
        {
            var connection = new Microsoft.Data.Sqlite.SqliteConnection(
                "DataSource=:memory:");
            connection.Open();

            var services = new ServiceCollection();
            services.AddLogging();
            services.AddDataProtection().UseEphemeralDataProtectionProvider();
            services.AddDbContextFactory<AppDbContext>(db =>
            {
                db.UseSqlite(connection);
                db.UseOpenIddict();
            });
            var provider = services.BuildServiceProvider();
            var dbFactory = provider.GetRequiredService<IDbContextFactory<AppDbContext>>();

            using (var db = dbFactory.CreateDbContext())
            {
                db.Database.EnsureCreated();
            }

            var options = new VaultOptions { Enabled = true };
            var kek = new DataProtectionKeySource(
                provider.GetRequiredService<IDataProtectionProvider>(),
                options);

            var vault = new KeyVault(
                dbFactory,
                kek,
                provider.GetRequiredService<ILogger<KeyVault>>(),
                options,
                new VaultCryptographyTelemetry(
                    options,
                    NullLogger<VaultCryptographyTelemetry>.Instance));

            return new VaultLeaseHarness(provider, connection, vault, kek);
        }

        /// <summary>A second vault instance sharing the same database.</summary>
        public KeyVault CreatePeerVault()
        {
            var options = new VaultOptions { Enabled = true };
            var dbFactory = _provider.GetRequiredService<IDbContextFactory<AppDbContext>>();
            return new KeyVault(
                dbFactory,
                new DataProtectionKeySource(
                    _provider.GetRequiredService<IDataProtectionProvider>(),
                    options),
                _provider.GetRequiredService<ILogger<KeyVault>>(),
                options,
                new VaultCryptographyTelemetry(
                    options,
                    NullLogger<VaultCryptographyTelemetry>.Instance));
        }

        public void SeedKey(string keyName, int version)
        {
            using var db = CreateDbContextAsync().GetAwaiter().GetResult();
            db.VaultKeys.Add(new VaultKey
            {
                KeyName = keyName,
                KeyVersion = version,
                Purpose = "symmetric",
                // A real DEK wrapped by the same KEK, so the re-read path can
                // actually unwrap and use it.
                WrappedKey = _kek.Wrap(
                    Sufficit.Identity.Vault.Crypto.EnvelopeCrypto.GenerateKey()),
                CreatedAtUtc = DateTime.UtcNow,
            });
            db.SaveChanges();
        }

        public void HoldLease(string keyName, TimeSpan expiresIn)
        {
            using var db = CreateDbContextAsync().GetAwaiter().GetResult();
            db.VaultSigningKeyLocks.Add(new VaultSigningKeyLock
            {
                KeyName = keyName,
                OwnerId = "other-replica",
                ExpiresAtUtc = DateTime.UtcNow.Add(expiresIn),
            });
            db.SaveChanges();
        }

        public VaultSigningKeyLock? GetLease(string keyName)
        {
            using var db = CreateDbContextAsync().GetAwaiter().GetResult();
            return db.VaultSigningKeyLocks
                .AsNoTracking()
                .FirstOrDefault(item => item.KeyName == keyName);
        }

        public async Task<AppDbContext> CreateDbContextAsync() =>
            await _provider.GetRequiredService<IDbContextFactory<AppDbContext>>()
                .CreateDbContextAsync();

        public void Dispose()
        {
            _provider.Dispose();
            _connection.Dispose();
        }
    }
}
