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

/// <summary>
/// Covers the internal secret vault: envelope crypto primitives, self-describing
/// ciphertext format, pass-through (disabled) round-trip, and the real KeyVault
/// (encrypt/decrypt/rotate with a SQLite-backed AppDbContext + EphemeralDataProtectionProvider).
/// </summary>
public sealed partial class VaultTests
{
    [Fact]
    public async Task Personal_secrets_are_scoped_by_owner_and_never_return_plaintext()
    {
        var options = new VaultOptions
        {
            Enabled = true,
            SigningKeyOverlapSeconds = 1,
        };
        var (vault, dbFactory) = CreateRealVault(options);
        var service = new UserVaultPersonalSecretService(
            new VaultBackedSecretStore(dbFactory, vault, options),
            options);

        await service.PutAsync(
            "user-a", "personal", "provider/api-key",
            new SaveUserVaultSecret("secret-a"));
        await service.PutAsync(
            "user-b", "personal", "provider/api-key",
            new SaveUserVaultSecret("secret-b"));

        var userA = await service.ListAsync("user-a", "personal");
        var userB = await service.ListAsync("user-b", "personal");

        Assert.Single(userA);
        Assert.Single(userB);
        Assert.Equal("user-a", userA[0].UpdatedBy);
        Assert.Equal("user-b", userB[0].UpdatedBy);
        Assert.Equal("provider/api-key", userA[0].Name);

        // Owners are separated by context, and the reserved root segment is what
        // the store persists as the namespace.
        await using var database = await dbFactory.CreateDbContextAsync();
        var stored = await database.VaultSecrets
            .OrderBy(secret => secret.ContextId)
            .ToArrayAsync();
        Assert.Equal(2, stored.Length);
        Assert.Equal(["user-user-a", "user-user-b"], stored.Select(item => item.ContextId));
        Assert.All(stored, item => Assert.Equal("personal", item.Namespace));
        Assert.All(stored, item => Assert.Equal("personal/provider/api-key", item.Name));
        Assert.DoesNotContain("secret-a", stored[0].Ciphertext, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-b", stored[1].Ciphertext, StringComparison.Ordinal);

        await service.DeleteAsync("user-a", "personal", "provider/api-key");
        Assert.Empty(await service.ListAsync("user-a", "personal"));
        Assert.Single(await service.ListAsync("user-b", "personal"));
    }

    /// <summary>
    /// Regression guard for the hazard created by merging user-typed secrets
    /// into the table that also holds connected credentials: without the
    /// reserved namespace, saving "oauth/tokens/github" under "integrations"
    /// would overwrite the user's own GitHub credential. Fails if either layer
    /// of the defence is removed.
    /// </summary>
    [Fact]
    public async Task Personal_secrets_cannot_reach_the_namespaces_owned_by_connected_applications()
    {
        var options = new VaultOptions { Enabled = true };
        var (vault, dbFactory) = CreateRealVault(options);
        var named = new VaultBackedSecretStore(dbFactory, vault, options);
        var service = new UserVaultPersonalSecretService(named, options);

        await named.PutAsync(
            "integrations/oauth/tokens/github",
            "connected-credential",
            "user-a",
            "user-user-a");

        // Layer one: an explicit non-personal namespace is refused, loudly.
        var rejected = await Assert.ThrowsAsync<ArgumentException>(
            () => service.PutAsync(
                "user-a",
                "integrations",
                "oauth/tokens/github",
                new SaveUserVaultSecret("attacker-value")));
        Assert.Contains("reserved", rejected.Message, StringComparison.OrdinalIgnoreCase);

        // Layer two: the same name accepted under the personal namespace lands
        // beside the credential, never on top of it.
        await service.PutAsync(
            "user-a",
            "personal",
            "oauth/tokens/github",
            new SaveUserVaultSecret("user-typed-value"));

        Assert.Equal(
            "connected-credential",
            await named.GetSecretAsync(
                "integrations/oauth/tokens/github",
                "user-user-a"));
        Assert.Equal(
            "user-typed-value",
            await named.GetSecretAsync(
                "personal/oauth/tokens/github",
                "user-user-a"));

        // Deleting through the personal boundary cannot reach the credential.
        await Assert.ThrowsAsync<ArgumentException>(
            () => service.DeleteAsync("user-a", "integrations", "oauth/tokens/github"));
        await service.DeleteAsync("user-a", "personal", "oauth/tokens/github");
        Assert.NotNull(await named.ResolveAsync(
            "integrations/oauth/tokens/github",
            "user-user-a"));
    }

    [Fact]
    public async Task Personal_overview_combines_user_typed_and_managed_metadata_without_pending_oauth_state()
    {
        var options = new VaultOptions
        {
            Enabled = true,
            SigningKeyOverlapSeconds = 300,
        };
        var (vault, dbFactory) = CreateRealVault(options);
        var named = new VaultBackedSecretStore(
            dbFactory,
            vault,
            options);
        var personal = new UserVaultPersonalSecretService(named, options);
        var overviewService = new UserVaultOverviewService(personal, named);

        await personal.PutAsync(
            "user-a",
            "personal",
            "provider/api-key",
            new SaveUserVaultSecret("user-typed-value"));
        await named.PutAsync(
            "integrations/oauth/tokens/github",
            "github-token",
            "user-a",
            "user-user-a");
        await named.PutAsync(
            "integrations/oauth/pending/temporary-state",
            "pending-ticket",
            "user-a",
            "user-user-a",
            DateTime.UtcNow.AddMinutes(15));
        await named.PutAsync(
            "providers/custom/api-key",
            "custom-value",
            "user-a",
            "user-user-a");
        await named.PutAsync(
            "integrations/oauth/tokens/gitlab",
            "other-user-token",
            "user-b",
            "user-user-b");

        var overview = await overviewService.GetAsync("user-a");

        Assert.Collection(
            overview.PersonalSecrets,
            item => Assert.Equal("provider/api-key", item.Name));
        Assert.Collection(
            overview.ManagedCredentials,
            github =>
            {
                Assert.Equal("integrations/oauth/tokens/github", github.Name);
                Assert.Equal("github", github.Provider);
            },
            custom =>
            {
                Assert.Equal("providers/custom/api-key", custom.Name);
                Assert.Null(custom.Provider);
            });
        Assert.DoesNotContain(
            overview.ManagedCredentials,
            item => item.Name.Contains("/pending/", StringComparison.Ordinal));
        Assert.DoesNotContain(
            overview.ManagedCredentials,
            item => item.Name.Contains("gitlab", StringComparison.Ordinal));
        // The two UI sections must stay disjoint now that they read one table:
        // a secret the user typed is never also a connected credential.
        Assert.DoesNotContain(
            overview.ManagedCredentials,
            item => item.Namespace == UserVaultPersonalSecretService.PersonalNamespace);
    }

    // ---- EnvelopeCrypto (AES-256-GCM) ----

    // ---- PassThroughKeyVault (disabled vault) ----

    // ---- KeyVault (real, with SQLite + EphemeralDataProtection) ----

    [Fact]
    public async Task Vault_snapshot_serves_encrypted_rows_from_memory_until_invalidation()
    {
        var (vault, dbFactory) = CreateRealVault();
        var cacheServices = new ServiceCollection();
        cacheServices.AddDistributedMemoryCache();
        using var cacheProvider = cacheServices.BuildServiceProvider();
        var snapshots = new VaultSnapshotCache(
            dbFactory,
            new VaultSnapshotOptions
            {
                LocalLifetimeSeconds = 60,
                DistributedLifetimeSeconds = 60,
            },
            NullLogger<VaultSnapshotCache>.Instance,
            cacheProvider.GetRequiredService<IDistributedCache>());
        var store = new VaultBackedSecretStore(
            dbFactory,
            vault,
            new VaultOptions { Enabled = true },
            snapshots);

        const string name = "providers/google/client-secret";
        const string context = "global";
        await store.PutAsync(name, "first-value", "operator-1", context);
        Assert.Equal("first-value", await store.GetSecretAsync(name, context));

        var replacementAad = new Dictionary<string, string>
        {
            ["scope"] = "named-secrets",
            ["name"] = name,
            ["namespace"] = "providers",
            ["context_id"] = context,
        };
        var replacementCiphertext = await vault.EncryptAsync(
            "named-secrets",
            "second-value",
            replacementAad);
        await using (var database = await dbFactory.CreateDbContextAsync())
        {
            var row = await database.VaultSecrets.SingleAsync(item =>
                item.Name == name && item.ContextId == context);
            row.Ciphertext = replacementCiphertext;
            row.AadJson = JsonSerializer.Serialize(replacementAad);
            await database.SaveChangesAsync();
        }

        // The request path remains memory-only while the snapshot is fresh.
        Assert.Equal("first-value", await store.GetSecretAsync(name, context));

        await snapshots.InvalidateSecretAsync(name, context);
        Assert.Equal("second-value", await store.GetSecretAsync(name, context));
    }

    [Fact]
    public async Task Vault_snapshot_reuses_public_signing_keys_without_reloading()
    {
        var (vault, dbFactory) = CreateRealVault();
        var cache = new VaultSnapshotCache(
            dbFactory,
            new VaultSnapshotOptions
            {
                LocalLifetimeSeconds = 60,
                DistributedLifetimeSeconds = 60,
            },
            NullLogger<VaultSnapshotCache>.Instance);
        var loadCount = 0;

        async Task<IReadOnlyList<VaultSigningKey>> Load(
            CancellationToken cancellationToken)
        {
            loadCount++;
            return await vault.GetSigningKeysAsync(
                "snapshot-signing",
                cancellationToken);
        }

        var first = await cache.GetSigningKeysAsync(
            "snapshot-signing",
            Load,
            CancellationToken.None);
        var second = await cache.GetSigningKeysAsync(
            "snapshot-signing",
            Load,
            CancellationToken.None);

        Assert.Single(first);
        Assert.Equal(first.Single().KeyId, second.Single().KeyId);
        Assert.Equal(1, loadCount);
    }

    [Fact]
    public async Task Vault_snapshot_remote_invalidation_clears_another_replica_memory_entry()
    {
        var (vault, dbFactory) = CreateRealVault();
        var bus = new RecordingVaultSnapshotInvalidationBus();
        var writerSnapshots = new VaultSnapshotCache(
            dbFactory,
            new VaultSnapshotOptions { LocalLifetimeSeconds = 60 },
            NullLogger<VaultSnapshotCache>.Instance,
            distributedCache: null,
            invalidationBus: bus);
        var readerSnapshots = new VaultSnapshotCache(
            dbFactory,
            new VaultSnapshotOptions { LocalLifetimeSeconds = 60 },
            NullLogger<VaultSnapshotCache>.Instance);
        var writer = new VaultBackedSecretStore(
            dbFactory,
            vault,
            new VaultOptions { Enabled = true },
            writerSnapshots);
        var reader = new VaultBackedSecretStore(
            dbFactory,
            vault,
            new VaultOptions { Enabled = true },
            readerSnapshots);

        const string name = "providers/redis/client-secret";
        const string context = "global";
        await writer.PutAsync(name, "first-value", "operator-1", context);
        Assert.Equal("first-value", await reader.GetSecretAsync(name, context));
        bus.Messages.Clear();

        var replacementAad = new Dictionary<string, string>
        {
            ["scope"] = "named-secrets",
            ["name"] = name,
            ["namespace"] = "providers",
            ["context_id"] = context,
        };
        var replacementCiphertext = await vault.EncryptAsync(
            "named-secrets",
            "second-value",
            replacementAad);
        await using (var database = await dbFactory.CreateDbContextAsync())
        {
            var row = await database.VaultSecrets.SingleAsync(item =>
                item.Name == name && item.ContextId == context);
            row.Ciphertext = replacementCiphertext;
            row.AadJson = JsonSerializer.Serialize(replacementAad);
            await database.SaveChangesAsync();
        }

        await writerSnapshots.InvalidateSecretAsync(name, context);
        var invalidation = Assert.Single(bus.Messages);
        readerSnapshots.ApplyRemoteInvalidation(invalidation);

        Assert.Equal("second-value", await reader.GetSecretAsync(name, context));
    }

    [Fact]
    public async Task Managed_signing_keys_use_snapshot_until_lifecycle_invalidation()
    {
        var options = new VaultOptions
        {
            Enabled = true,
            ManageSigningKeys = true,
            SigningKeyOverlapSeconds = 300,
        };
        var (vault, dbFactory) = CreateRealVault(options, withSnapshots: true);

        var first = await vault.GetSigningKeysAsync("managed-snapshot-signing");
        Assert.Single(first);

        await using (var database = await dbFactory.CreateDbContextAsync())
        {
            var row = await database.VaultKeys.SingleAsync(key =>
                key.KeyName == "managed-snapshot-signing"
                && key.Purpose == "signing");
            row.SigningState = VaultSigningKeyState.Revoked;
            await database.SaveChangesAsync();
        }

        // An out-of-band DB mutation is intentionally invisible until the
        // snapshot is invalidated; normal lifecycle APIs publish invalidation.
        Assert.Single(await vault.GetSigningKeysAsync("managed-snapshot-signing"));

        Assert.IsType<KeyVault>(vault).FlushCache();
        Assert.Empty(await vault.GetSigningKeysAsync("managed-snapshot-signing"));
    }

    // ---- VaultBackedClientSecretResolver (M1 fix) ----

    // ---- Helpers ----

    private static (IKeyVault vault, IDbContextFactory<AppDbContext> dbFactory) CreateRealVault(
        VaultOptions? options = null,
        TimeProvider? timeProvider = null,
        Func<IDataProtectionProvider, IVaultKeyEncryptionKeySource>? keySourceFactory = null,
        bool withSnapshots = false,
        bool allowPlaintextRead = false,
        DateTimeOffset? plaintextReadDeadline = null)
    {
        // Hold a single in-memory SQLite connection open for the lifetime of
        // the test so every DbContext created by the factory shares the same
        // database (SQLite :memory: is per-connection).
        var connection = new Microsoft.Data.Sqlite.SqliteConnection("DataSource=:memory:");
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

        // Ensure schema exists.
        using var db = dbFactory.CreateDbContext();
        db.Database.EnsureCreated();

        var dpProvider = provider.GetRequiredService<IDataProtectionProvider>();
        options ??= new VaultOptions
        {
            Enabled = true,
            // RSA-3072 generation can take longer than one second on a CI
            // runner. Keep the default overlap comfortably above test
            // execution time; expiry behavior is covered with an explicit
            // short window in the lifecycle tests.
            SigningKeyOverlapSeconds = 300,
        };
        var kek = keySourceFactory?.Invoke(dpProvider)
            ?? new DataProtectionKeySource(dpProvider, options);
        var logger = provider.GetRequiredService<ILogger<KeyVault>>();
        IKeyVault vault;
        if (withSnapshots)
        {
            var snapshots = new VaultSnapshotCache(
                dbFactory,
                options.Snapshot,
                NullLogger<VaultSnapshotCache>.Instance);
            vault = new KeyVault(
                dbFactory,
                kek,
                logger,
                options,
                new VaultCryptographyTelemetry(
                    options,
                    NullLogger<VaultCryptographyTelemetry>.Instance),
                timeProvider,
                snapshots,
                allowPlaintextRead,
                plaintextReadDeadline);
        }
        else
        {
            vault = new KeyVault(
                dbFactory,
                kek,
                logger,
                options,
                new VaultCryptographyTelemetry(
                    options,
                    NullLogger<VaultCryptographyTelemetry>.Instance),
                timeProvider,
                snapshots: null,
                allowPlaintextReadCompatibility: allowPlaintextRead,
                plaintextReadCompatibilityExpiresAtUtc: plaintextReadDeadline);
        }
        return (vault, dbFactory);
    }

    private sealed class MutableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan duration) => _utcNow += duration;
    }

    private sealed class RecordingVaultSnapshotInvalidationBus
        : IVaultSnapshotInvalidationBus
    {
        public List<VaultSnapshotInvalidation> Messages { get; } = [];

        public Task PublishAsync(
            VaultSnapshotInvalidation invalidation,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Messages.Add(invalidation);
            return Task.CompletedTask;
        }

        public Task SubscribeAsync(
            Func<VaultSnapshotInvalidation, Task> handler,
            CancellationToken cancellationToken) => Task.CompletedTask;

        public Task UnsubscribeAsync(CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class FailingKeySource(IVaultKeyEncryptionKeySource inner)
        : IVaultKeyEncryptionKeySource
    {
        public bool FailWrap { get; set; }

        public string KeyIdentifier => "test:failable";

        public byte[] Wrap(ReadOnlyMemory<byte> dek) => FailWrap
            ? throw new CryptographicException("Simulated KEK loss.")
            : inner.Wrap(dek);

        public byte[] Unwrap(ReadOnlyMemory<byte> wrappedDek) =>
            inner.Unwrap(wrappedDek);
    }

    private sealed class XorExternalKeyEncryptionProvider(string keyIdentifier)
        : IVaultExternalKeyEncryptionProvider
    {
        public string KeyIdentifier => keyIdentifier;

        public byte[] Wrap(ReadOnlyMemory<byte> plaintextKey) =>
            plaintextKey.Span.ToArray().Select(value => (byte)(value ^ 0xA5)).ToArray();

        public byte[] Unwrap(ReadOnlyMemory<byte> wrappedKey) => Wrap(wrappedKey);
    }

    private sealed class AllowingManagementAuthorizationEvaluator
        : IManagementAuthorizationEvaluator
    {
        public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
            ClaimsPrincipal principal,
            string capability,
            ManagementResource resource,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(
                ManagementAuthorizationDecision.Allowed());
        }
    }

    private sealed class DictionarySecretStore(
        IReadOnlyDictionary<string, string?> values) : ISecretStore
    {
        public List<string> RequestedNames { get; } = [];

        public Task<string?> GetSecretAsync(
            string name,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RequestedNames.Add(name);
            values.TryGetValue(name, out var value);
            return Task.FromResult(value);
        }
    }
}
