using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Vault;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// F-2 (eval 2026-08-14): the real vault must reject the legacy
/// <c>pt1.</c> plaintext pass-through outside Development. A tampered
/// database/Redis row swapped for <c>pt1.&lt;base64url&gt;</c> would otherwise
/// resolve to attacker-chosen plaintext (e.g. a client-secret reference
/// consumed during provisioning). Reading the marker is allowed only in
/// Development or through a bounded, attributed compatibility window whose
/// deadline is enforced at read time.
/// </summary>
public sealed class VaultPlaintextCompatibilityTests
{
    private const string Marker = "pt1.";

    [Fact]
    public async Task Decrypt_pt1_is_rejected_by_default()
    {
        // Default construction (no compatibility window): the marker must
        // fail closed instead of returning attacker-chosen "plaintext".
        using var harness = VaultHarness.Create();

        var exception = await Assert.ThrowsAsync<CryptographicException>(() =>
            harness.Vault.DecryptAsync(Marker + Encode("attacker-chosen")));

        Assert.Contains("PlaintextReadCompatibility", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Decrypt_pt1_is_readable_within_the_bounded_window()
    {
        var time = new MutableTimeProvider();
        using var harness = VaultHarness.Create(
            allowPlaintextRead: true,
            deadline: time.GetUtcNow().AddMinutes(30),
            timeProvider: time);

        var plaintext = await harness.Vault.DecryptAsync(
            Marker + Encode("legacy-value"));

        Assert.Equal("legacy-value"u8.ToArray(), plaintext.ToArray());
    }

    [Fact]
    public async Task Decrypt_pt1_stops_being_readable_once_the_window_expires()
    {
        // The deadline is enforced per read, so a process that outlives the
        // acknowledged window rejects the marker without a restart.
        var time = new MutableTimeProvider();
        using var harness = VaultHarness.Create(
            allowPlaintextRead: true,
            deadline: time.GetUtcNow().AddMinutes(5),
            timeProvider: time);

        var ciphertext = Marker + Encode("legacy-value");
        // DecryptAsync returns ReadOnlyMemory<byte> (a value type) — assert
        // its length rather than a null check on a value (xUnit2002).
        var inWindow = await harness.Vault.DecryptAsync(ciphertext);
        Assert.Equal("legacy-value".Length, inWindow.Length);

        time.Advance(TimeSpan.FromMinutes(6));

        await Assert.ThrowsAsync<CryptographicException>(() =>
            harness.Vault.DecryptAsync(ciphertext));
    }

    [Fact]
    public void Plaintext_read_compatibility_window_is_bounded_and_attributed()
    {
        var now = new DateTimeOffset(2026, 8, 14, 12, 0, 0, TimeSpan.Zero);

        // Owner/Reason/ExpiresAtUtc must be supplied together.
        Assert.Throws<InvalidOperationException>(() =>
            Sufficit.Identity.Vault.ServiceCollectionExtensions
                .ValidatePlaintextReadCompatibility(
                    new VaultPlaintextReadCompatibilityOptions
                    {
                        Owner = "identity-platform",
                        ExpiresAtUtc = now.AddDays(30),
                    },
                    now));

        // Expired windows are rejected at startup.
        Assert.Throws<InvalidOperationException>(() =>
            Sufficit.Identity.Vault.ServiceCollectionExtensions
                .ValidatePlaintextReadCompatibility(
                    new VaultPlaintextReadCompatibilityOptions
                    {
                        Owner = "identity-platform",
                        Reason = "rewrite remaining pt1 rows",
                        ExpiresAtUtc = now,
                    },
                    now));

        // The window cannot exceed 180 days.
        Assert.Throws<InvalidOperationException>(() =>
            Sufficit.Identity.Vault.ServiceCollectionExtensions
                .ValidatePlaintextReadCompatibility(
                    new VaultPlaintextReadCompatibilityOptions
                    {
                        Owner = "identity-platform",
                        Reason = "rewrite remaining pt1 rows",
                        ExpiresAtUtc = now.AddDays(181),
                    },
                    now));

        // A complete, in-window acknowledgement passes.
        Sufficit.Identity.Vault.ServiceCollectionExtensions
            .ValidatePlaintextReadCompatibility(
                new VaultPlaintextReadCompatibilityOptions
                {
                    Owner = "identity-platform",
                    Reason = "rewrite remaining pt1 rows",
                    ExpiresAtUtc = now.AddDays(30),
                },
                now);
    }

    private static string Encode(string value) =>
        Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(
            System.Text.Encoding.UTF8.GetBytes(value));

    private sealed class MutableTimeProvider : TimeProvider
    {
        private DateTimeOffset _utcNow = new(2026, 8, 14, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan delta) => _utcNow += delta;
    }

    /// <summary>
    /// Minimal real-vault harness: SQLite in-memory schema + ephemeral Data
    /// Protection KEK, mirroring VaultTests.CreateRealVault without the
    /// signing-key surface. The pt1 branch short-circuits before any database
    /// access, so a single shared schema is enough.
    /// </summary>
    private sealed class VaultHarness : IDisposable
    {
        private readonly ServiceProvider _provider;
        private readonly Microsoft.Data.Sqlite.SqliteConnection _connection;

        private VaultHarness(
            ServiceProvider provider,
            Microsoft.Data.Sqlite.SqliteConnection connection,
            KeyVault vault)
        {
            _provider = provider;
            _connection = connection;
            Vault = vault;
        }

        public KeyVault Vault { get; }

        public static VaultHarness Create(
            bool allowPlaintextRead = false,
            DateTimeOffset? deadline = null,
            TimeProvider? timeProvider = null)
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
                    NullLogger<VaultCryptographyTelemetry>.Instance),
                timeProvider,
                snapshots: null,
                allowPlaintextReadCompatibility: allowPlaintextRead,
                plaintextReadCompatibilityExpiresAtUtc: deadline);

            return new VaultHarness(provider, connection, vault);
        }

        public void Dispose()
        {
            _provider.Dispose();
            _connection.Dispose();
        }
    }
}

/// <summary>Test-only convenience so the harness reads naturally.</summary>
internal static class KeyVaultTestExtensions
{
    public static Task<System.ReadOnlyMemory<byte>> DecryptAsync(
        this KeyVault vault,
        string ciphertext) =>
        vault.DecryptAsync(ciphertext);
}
