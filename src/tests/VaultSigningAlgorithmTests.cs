using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Vault;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// A6 (eval 2026-08-14): signing-algorithm agility for vault-managed keys.
/// Each key VERSION embeds its algorithm in the stored public JWK; a new or
/// rotated version uses <c>VaultOptions.SigningAlgorithm</c> (RS256 default,
/// PS256 or ES256), while verification, re-signing and JWKS publication
/// always follow the version's own algorithm — so rotation may move between
/// families without invalidating in-flight versions.
/// </summary>
public sealed class VaultSigningAlgorithmTests
{
    [Fact]
    public async Task Default_creation_stays_rs256()
    {
        using var harness = Harness.Create();

        var keys = await harness.Vault.GetSigningKeysAsync("oidc-signing");
        var jwk = Assert.Single(keys).PublicJwk;

        Assert.Equal(
            SigningAlgorithms.RsaSha256,
            SigningAlgorithms.FromJwk(jwk));
        Assert.False(SigningAlgorithms.IsEc(jwk));

        await AssertRoundTripsAsync(harness, "oidc-signing");
    }

    [Fact]
    public async Task Es256_creation_produces_ec_keys_that_round_trip()
    {
        using var harness = Harness.Create(
            new VaultOptions
            {
                Enabled = true,
                SigningAlgorithm = SigningAlgorithms.EcdsaSha256,
                SigningKeyOverlapSeconds = 300,
            });

        var keys = await harness.Vault.GetSigningKeysAsync("oidc-signing");
        var jwk = Assert.Single(keys).PublicJwk;

        Assert.Equal(
            SigningAlgorithms.EcdsaSha256,
            SigningAlgorithms.FromJwk(jwk));
        Assert.True(SigningAlgorithms.IsEc(jwk));

        await AssertRoundTripsAsync(harness, "oidc-signing");
    }

    [Fact]
    public async Task Ps256_creation_round_trips_with_pss_padding()
    {
        using var harness = Harness.Create(
            new VaultOptions
            {
                Enabled = true,
                SigningAlgorithm = SigningAlgorithms.RsaPssSha256,
                SigningKeyOverlapSeconds = 300,
            });

        await AssertRoundTripsAsync(harness, "oidc-signing");
    }

    [Fact]
    public async Task Rotation_between_families_keeps_the_old_version_verifiable()
    {
        // v1 is created under RS256; the deployment then switches the
        // configuration to ES256 and rotates. v1 must still sign-verify with
        // PKCS#1 v1.5 while v2 is an EC/ES256 key — the algorithm travels
        // with the VERSION, not with the configuration.
        using var harness = Harness.Create();
        await harness.Vault.GetSigningKeysAsync("oidc-signing");

        var rotated = harness.CreatePeer(new VaultOptions
        {
            Enabled = true,
            SigningAlgorithm = SigningAlgorithms.EcdsaSha256,
            SigningKeyOverlapSeconds = 300,
        });
        await rotated.RotateSigningKeyAsync(
            "oidc-signing",
            "rotate-to-es256",
            "algorithm agility test");

        var keys = await harness.Vault.GetSigningKeysAsync("oidc-signing");
        Assert.Equal(2, keys.Count);
        Assert.Contains(keys, key =>
            SigningAlgorithms.FromJwk(key.PublicJwk) == SigningAlgorithms.RsaSha256);
        Assert.Contains(keys, key =>
            SigningAlgorithms.FromJwk(key.PublicJwk) == SigningAlgorithms.EcdsaSha256);

        // The ES256 v2 is the active signer; the RS256 v1 stays verifiable
        // inside its overlap window (verify-by-version uses its own family).
        var envelope = await harness.Vault.SignAsync(
            "oidc-signing",
            "payload"u8.ToArray());
        Assert.Contains("oidc-signing:2", envelope, StringComparison.Ordinal);
        Assert.True(await harness.Vault.VerifyAsync(
            envelope, "payload"u8.ToArray()));
    }

    [Fact]
    public async Task Es256_signature_uses_the_joy_p1363_r_s_format()
    {
        // JOSE ECDSA signatures are raw R||S (64 bytes for P-256), not DER.
        using var harness = Harness.Create(
            new VaultOptions
            {
                Enabled = true,
                SigningAlgorithm = SigningAlgorithms.EcdsaSha256,
                SigningKeyOverlapSeconds = 300,
            });

        var envelope = await harness.Vault.SignAsync(
            "oidc-signing",
            "payload"u8.ToArray());
        var separator = envelope.LastIndexOf('.');
        var signature = Microsoft.AspNetCore.WebUtilities.WebEncoders
            .Base64UrlDecode(envelope[(separator + 1)..]);

        Assert.Equal(64, signature.Length);
    }

    /// <summary>
    /// Regression (eval 2026-08-23, S-2): the snapshot cache is enabled by
    /// default (<see cref="VaultSnapshotOptions.Enabled"/>), and the cached
    /// verification path used to hardcode RSA with PKCS#1 v1.5 padding while
    /// the database path dispatched on the version's own JWK. Every ES256 and
    /// PS256 signature was therefore rejected as invalid in any deployment
    /// running the default configuration — the algorithm-agility tests above
    /// missed it because their harness has no snapshot cache attached.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.RsaSha256)]
    [InlineData(SigningAlgorithms.RsaPssSha256)]
    [InlineData(SigningAlgorithms.EcdsaSha256)]
    public async Task Snapshot_verification_honors_the_version_algorithm(
        string algorithm)
    {
        using var harness = Harness.Create(
            new VaultOptions
            {
                Enabled = true,
                SigningAlgorithm = algorithm,
                SigningKeyOverlapSeconds = 300,
            },
            withSnapshots: true);

        await AssertRoundTripsAsync(harness, "oidc-signing");
    }

    [Fact]
    public void Unsupported_algorithm_is_rejected_at_validation_time()
    {
        Assert.Throws<InvalidOperationException>(() =>
            Sufficit.Identity.Vault.ServiceCollectionExtensions
                .ValidateKeyEncryptionKeyPolicy(
                    new VaultOptions
                    {
                        Enabled = true,
                        SigningAlgorithm = "HS256",
                    },
                    new Microsoft.Extensions.Configuration.ConfigurationBuilder()
                        .AddInMemoryCollection(new Dictionary<string, string?>
                        {
                            ["Sufficit:Vault:CertificatePath"] = "/nonexistent.pfx",
                        })
                        .Build(),
                    isDevelopment: false,
                    secretStore: new EnvironmentSecretStore()));
    }

    private static async Task AssertRoundTripsAsync(
        Harness harness,
        string keyName)
    {
        var payload = "round-trip"u8.ToArray();
        var envelope = await harness.Vault.SignAsync(keyName, payload);
        Assert.StartsWith("sig1." + keyName + ":", envelope, StringComparison.Ordinal);
        Assert.True(await harness.Vault.VerifyAsync(envelope, payload));
        Assert.False(await harness.Vault.VerifyAsync(envelope, "tampered"u8.ToArray()));
    }

    private sealed class Harness : IDisposable
    {
        private readonly ServiceProvider _provider;
        private readonly Microsoft.Data.Sqlite.SqliteConnection _connection;

        private Harness(
            ServiceProvider provider,
            Microsoft.Data.Sqlite.SqliteConnection connection,
            KeyVault vault)
        {
            _provider = provider;
            _connection = connection;
            Vault = vault;
        }

        public KeyVault Vault { get; }

        public static Harness Create(
            VaultOptions? options = null,
            bool withSnapshots = false)
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

            options ??= new VaultOptions
            {
                Enabled = true,
                // Comfortable overlap for CI runners (see VaultTests notes).
                SigningKeyOverlapSeconds = 300,
            };
            var kek = new DataProtectionKeySource(
                provider.GetRequiredService<IDataProtectionProvider>(),
                options);

            // Production runs with the snapshot cache attached by default, so
            // the cached read path must be exercised too — not only the
            // database fallback the other tests here reach.
            var snapshots = withSnapshots
                ? new VaultSnapshotCache(
                    dbFactory,
                    new VaultSnapshotOptions(),
                    provider.GetRequiredService<ILogger<VaultSnapshotCache>>())
                : null;

            var vault = new KeyVault(
                dbFactory,
                kek,
                provider.GetRequiredService<ILogger<KeyVault>>(),
                options,
                new VaultCryptographyTelemetry(
                    options,
                    NullLogger<VaultCryptographyTelemetry>.Instance),
                timeProvider: null,
                snapshots: snapshots);

            return new Harness(provider, connection, vault);
        }

        /// <summary>
        /// A second vault instance sharing the database, bound to different
        /// options — the "deployment switched configuration" stand-in.
        /// </summary>
        public KeyVault CreatePeer(VaultOptions options)
        {
            var dbFactory = _provider
                .GetRequiredService<IDbContextFactory<AppDbContext>>();
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

        public void Dispose()
        {
            _provider.Dispose();
            _connection.Dispose();
        }
    }
}
