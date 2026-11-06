using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Server;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class MariaDbHistoricalHostTests
{
    private const string HostVariable = "SUFFICIT_TEST_HISTORICAL_HOST_DLL";

    public sealed class HistoricalHostFactAttribute : FactAttribute
    {
        public HistoricalHostFactAttribute()
        {
            if (Environment.GetEnvironmentVariable("SUFFICIT_TEST_MARIADB_DOCKER") != "1"
                || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(HostVariable)))
                Skip = "Requires owned MariaDB opt-in and an explicitly selected historical host DLL.";
        }
    }

    [HistoricalHostFact]
    [Trait("Category", "MariaDbIntegration")]
    public async Task Historical_http_host_serves_readiness_after_current_schema_upgrade()
    {
        var assembly = Path.GetFullPath(Environment.GetEnvironmentVariable(HostVariable)!);
        Assert.True(File.Exists(assembly));
        Assert.NotEqual(typeof(HostBootstrap).Assembly.Location, assembly);
        await using var server = new SessionTicketMariaDbOutageTests.LocalMariaDb();
        await server.CreateAsync();
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseMySql(server.ConnectionString, new MariaDbServerVersion(new Version(10, 11)),
                mysql => mysql.MigrationsHistoryTable(IdentityDatabaseSchema.MigrationsHistoryTable)).Options;
        await using var db = new AppDbContext(options);
        await HostBootstrap.ApplyMigrationsWithAdvisoryLockAsync(db);
        var applied = (await db.Database.GetAppliedMigrationsAsync()).ToArray();
        Assert.Contains(IdentityDatabaseSchema.TokenMaintenanceMigrationId, applied);
        var directory = Path.Combine(Path.GetTempPath(), "identity-historical-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=historical-test", rsa,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),
                DateTimeOffset.UtcNow.AddDays(1));
            var path = Path.Combine(directory, "test.pfx");
            await File.WriteAllBytesAsync(path, certificate.Export(X509ContentType.Pfx));
            var listening = new TaskCompletionSource<Uri>(TaskCreationOptions.RunContinuationsAsynchronously);
            var log = new StringBuilder();
            void Output(object sender, DataReceivedEventArgs args)
            {
                if (args.Data is not { } line) return;
                lock (log) log.AppendLine(line);
                const string marker = "Now listening on: ";
                var at = line.IndexOf(marker, StringComparison.Ordinal);
                if (at >= 0 && Uri.TryCreate(line[(at + marker.Length)..].Trim(), UriKind.Absolute, out var uri))
                    listening.TrySetResult(uri);
            }
            using var process = MariaDbMigratorProcessTests.Start(directory, path, server.ConnectionString,
                assembly, migrateOnly: false, output: Output);
            var error = process.StandardError.ReadToEndAsync();
            try
            {
                var exit = process.WaitForExitAsync();
                var first = await Task.WhenAny(listening.Task, exit).WaitAsync(TimeSpan.FromSeconds(60));
                if (first == exit)
                    Assert.Fail($"Historical host exited {process.ExitCode}: {log}\n{await error}");
                var address = await listening.Task;
                Assert.True(address.IsLoopback);
                using var http = new HttpClient { BaseAddress = address, Timeout = TimeSpan.FromSeconds(15) };
                using var response = await http.GetAsync("/health/ready");
                Assert.True(response.IsSuccessStatusCode,
                    $"Readiness returned {response.StatusCode}: {await response.Content.ReadAsStringAsync()}");
                Assert.Equal(applied, (await db.Database.GetAppliedMigrationsAsync()).ToArray());
                Assert.Empty(await db.Database.GetPendingMigrationsAsync());
            }
            finally
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
        }
        finally { Directory.Delete(directory, recursive: true); }
    }
}
