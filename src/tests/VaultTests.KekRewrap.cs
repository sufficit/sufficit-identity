using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.STS.Security;
using Sufficit.Identity.Vault;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class VaultTests
{
    private const string KekPassword = "test-only-password";

    [Fact]
    public void A_previous_kek_only_unwraps_and_the_active_one_alone_wraps()
    {
        using var directory = new KekDirectory();
        var oldPath = directory.Create("old");
        var newPath = directory.Create("new");
        using var oldSource = Source(oldPath);
        using var rotated = Source(newPath, oldPath);
        var dek = RandomNumberGenerator.GetBytes(32);

        var underOld = oldSource.Wrap(dek);
        Assert.Equal(dek, rotated.Unwrap(underOld));
        Assert.False(rotated.IsWrappedByActiveKey(underOld));
        Assert.True(rotated.IsWrappedByActiveKey(rotated.Wrap(dek)));
        Assert.True(rotated.HasPreviousKeys);

        using var newOnly = Source(newPath);
        Assert.ThrowsAny<CryptographicException>(() => newOnly.Unwrap(underOld));
    }

    [Fact]
    public async Task Rewrap_moves_every_data_key_to_the_active_kek_and_is_idempotent()
    {
        using var directory = new KekDirectory();
        var oldPath = directory.Create("old");
        var newPath = directory.Create("new");
        using var oldSource = Source(oldPath);
        var (oldVault, factory) = CreateRealVault(keySourceFactory: _ => oldSource);
        var first = await oldVault.EncryptAsync("rewrap-a", "alpha");
        await oldVault.RotateKeyAsync("rewrap-a");
        var second = await oldVault.EncryptAsync("rewrap-a", "beta");
        var third = await oldVault.EncryptAsync("rewrap-b", "gamma");

        using var rotated = Source(newPath, oldPath);
        var rewrap = (IVaultKekRewrap)Vault(factory, rotated);
        var result = await rewrap.RewrapAsync("op-kek-1", "test rotation");

        Assert.Equal(3, result.Rewrapped);
        Assert.Empty(result.Failed);
        Assert.False(result.AlreadyCompleted);

        // The old KEK is gone: the new one alone still opens what the old one wrote.
        using var newOnly = Source(newPath);
        var newVault = Vault(factory, newOnly);
        Assert.Equal("alpha", await newVault.DecryptStringAsync(first));
        Assert.Equal("beta", await newVault.DecryptStringAsync(second));
        Assert.Equal("gamma", await newVault.DecryptStringAsync(third));

        var again = await rewrap.RewrapAsync("op-kek-1", "test rotation");
        Assert.True(again.AlreadyCompleted);
        var fresh = await rewrap.RewrapAsync("op-kek-2", "second pass");
        Assert.Equal(0, fresh.Rewrapped);
        Assert.Equal(3, fresh.AlreadyActive);
    }

    [Fact]
    public async Task Rewrap_reports_a_key_no_configured_kek_opens_and_journals_nothing()
    {
        using var directory = new KekDirectory();
        var lostPath = directory.Create("lost");
        var newPath = directory.Create("new");
        using var lostSource = Source(lostPath);
        var (lostVault, factory) = CreateRealVault(keySourceFactory: _ => lostSource);
        await lostVault.EncryptAsync("rewrap-lost", "orphan");

        using var unrelated = Source(newPath);
        var result = await ((IVaultKekRewrap)Vault(factory, unrelated)).RewrapAsync("op-kek-lost", "test");

        Assert.Equal(new KeyId("rewrap-lost", 1), Assert.Single(result.Failed));
        await using var db = await factory.CreateDbContextAsync();
        Assert.False(await db.VaultSigningKeyLifecycleOperations.AnyAsync(entry => entry.OperationId == "op-kek-lost"));
    }

    [Fact]
    public async Task Rewrap_moves_the_data_protection_key_ring_to_the_active_certificate()
    {
        using var directory = new KekDirectory();
        var oldPath = directory.Create("old");
        var newPath = directory.Create("new");
        using var oldCertificate = X509CertificateLoader.LoadPkcs12FromFile(oldPath, KekPassword);
        using var newCertificate = X509CertificateLoader.LoadPkcs12FromFile(newPath, KekPassword);
        using var connection = new Microsoft.Data.Sqlite.SqliteConnection("DataSource=:memory:");
        connection.Open();

        string protectedPayload;
        using (var before = KeyRingServices(connection, oldCertificate))
        {
            using var scope = before.CreateScope();
            await scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.EnsureCreatedAsync();
            protectedPayload = before.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector("kek-rewrap-test").Protect("payload");
        }

        using (var rotated = KeyRingServices(connection, newCertificate, oldCertificate))
        {
            using var scope = rotated.CreateScope();
            var result = await DataProtectionKeyRingRewrap.RewrapAsync(
                scope.ServiceProvider.GetRequiredService<AppDbContext>(),
                rotated,
                newCertificate,
                NullLoggerFactory.Instance);
            Assert.True(result.Rewrapped >= 1);
            Assert.Empty(result.Failed);
        }

        using var after = KeyRingServices(connection, newCertificate);
        Assert.Equal("payload", after.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("kek-rewrap-test").Unprotect(protectedPayload));
    }

    [Fact]
    public void A_configured_previous_kek_is_a_posture_advisory()
    {
        var findings = new VaultProductionPostureContributor(new VaultOptions
        {
            Enabled = true,
            KeySource = "certificate",
            PreviousCertificatePaths = ["vault-kek.old.pfx"],
        }).Evaluate();

        Assert.Contains(findings, finding => finding.Id == "vault-kek-previous-configured");
    }

    private static CertificateKeySource Source(string path, params string[] previous) =>
        new(new VaultOptions
        {
            CertificatePath = path,
            CertificatePassword = KekPassword,
            PreviousCertificatePaths = previous,
        });

    private static IKeyVault Vault(IDbContextFactory<AppDbContext> factory, IVaultKeyEncryptionKeySource source) =>
        new KeyVault(factory, source, NullLogger<KeyVault>.Instance, new VaultOptions { Enabled = true });

    private static ServiceProvider KeyRingServices(
        Microsoft.Data.Sqlite.SqliteConnection connection,
        X509Certificate2 protect,
        params X509Certificate2[] alsoUnprotect)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<AppDbContext>(db =>
        {
            db.UseSqlite(connection);
            db.UseOpenIddict();
        });
        services.AddDataProtection()
            .SetApplicationName("kek-rewrap-test")
            .PersistKeysToDbContext<AppDbContext>()
            .ProtectKeysWithCertificate(protect)
            .UnprotectKeysWithAnyCertificate([protect, .. alsoUnprotect]);
        return services.BuildServiceProvider();
    }

    private sealed class KekDirectory : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("vault-kek-rewrap-");

        public string Create(string name)
        {
            using var rsa = RSA.Create(3072);
            var request = new CertificateRequest(
                $"CN=vault-kek-{name}.tests.local", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(30));
            var path = Path.Combine(_directory.FullName, $"{name}.pfx");
            File.WriteAllBytes(path, certificate.Export(X509ContentType.Pfx, KekPassword));
            return path;
        }

        public void Dispose() => _directory.Delete(recursive: true);
    }
}
