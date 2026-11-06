using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Server;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class MariaDbMigratorProcessTests
{
    [SessionTicketMariaDbOutageTests.LocalMariaDbFact]
    [Trait("Category", "MariaDbIntegration")]
    public async Task Two_dedicated_host_processes_complete_without_starting_http()
    {
        await using var server = new SessionTicketMariaDbOutageTests.LocalMariaDb();
        await server.CreateAsync();
        var directory = Path.Combine(Path.GetTempPath(), "identity-migrator-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=migrator-test", rsa,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),
                DateTimeOffset.UtcNow.AddDays(1));
            var certificatePath = Path.Combine(directory, "test.pfx");
            await File.WriteAllBytesAsync(certificatePath, certificate.Export(X509ContentType.Pfx));
            var children = new List<(Process Process, Task<string> Output, Task<string> Error)>();
            try
            {
                for (var i = 0; i < 2; i++)
                {
                    var process = Start(directory, certificatePath, server.ConnectionString);
                    children.Add((process, process.StandardOutput.ReadToEndAsync(), process.StandardError.ReadToEndAsync()));
                }
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
                await Task.WhenAll(children.Select(child => child.Process.WaitForExitAsync(timeout.Token)));
                foreach (var child in children)
                    Verify(child.Process.ExitCode, await child.Output, await child.Error);
            }
            finally
            {
                foreach (var child in children)
                {
                    if (!child.Process.HasExited) child.Process.Kill(entireProcessTree: true);
                    await child.Process.WaitForExitAsync();
                    child.Process.Dispose();
                }
            }
            var options = new DbContextOptionsBuilder<AppDbContext>()
                .UseMySql(server.ConnectionString, new MariaDbServerVersion(new Version(10, 11)),
                    mysql => mysql.MigrationsHistoryTable(IdentityDatabaseSchema.MigrationsHistoryTable)).Options;
            await using var db = new AppDbContext(options);
            Assert.Equal(db.Database.GetMigrations().ToArray(),
                (await db.Database.GetAppliedMigrationsAsync()).ToArray());
            Assert.Empty(await db.Database.GetPendingMigrationsAsync());
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    internal static Process Start(string directory, string certificate, string connection,
        string? assemblyPath = null, bool migrateOnly = true, DataReceivedEventHandler? output = null)
    {
        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = directory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        // Do not inherit deployment secrets, config overrides or startup hooks.
        start.Environment.Clear();
        start.Environment["PATH"] = Environment.GetEnvironmentVariable("PATH");
        foreach (var surface in new[] { "Public", "Management", "Vault" })
            start.Environment[$"Sufficit__Identity__UI__{surface}__Mode"] = "None";
        start.Environment["DOTNET_ENVIRONMENT"] = "Development";
        start.Environment["ASPNETCORE_ENVIRONMENT"] = "Development";
        start.Environment["SUFFICIT_SECRET_DATABASE_CONNECTION_STRING"] = connection;
        // The fixture supplies its own certificate instead of modifying the user certificate store.
        start.Environment["Sufficit__Identity__AllowDevelopmentOnPublicHost"] = "true";
        start.Environment["Sufficit__Identity__Issuer"] = "https://localhost/";
        start.Environment["Sufficit__Identity__Database__AllowedDatabaseNames__0"] = "session_test";
        start.Environment["Sufficit__Identity__Certificates__SigningPath"] = certificate;
        start.Environment["Sufficit__Identity__Certificates__EncryptionPath"] = certificate;
        start.Environment["ASPNETCORE_URLS"] = "http://127.0.0.1:0";
        start.ArgumentList.Add(assemblyPath ?? typeof(HostBootstrap).Assembly.Location);
        start.ArgumentList.Add("--contentRoot");
        start.ArgumentList.Add(directory);
        if (migrateOnly) start.ArgumentList.Add("--migrate-only");
        var process = new Process { StartInfo = start };
        if (output is not null) process.OutputDataReceived += output;
        try
        {
            if (!process.Start()) throw new InvalidOperationException("Could not launch disposable host.");
            if (output is not null) process.BeginOutputReadLine();
            return process;
        }
        catch { process.Dispose(); throw; }
    }

    private static void Verify(int exitCode, string output, string error)
    {
        Assert.True(exitCode == 0, $"Migrator exited {exitCode}: {output}\n{error}");
        Assert.Contains("Dedicated migration job completed; the HTTP host will not start.", output);
        Assert.DoesNotContain("Now listening on:", output);
    }
}
