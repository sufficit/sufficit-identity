using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.Server;

/// <summary>
/// Startup and maintenance routines used by the composition host: parsing the
/// target database out of a connection string, the one-shot metrics-credential
/// repair command, and applying migrations under a MySQL advisory lock.
/// </summary>
/// <remarks>
/// Extracted from Program.cs so the composition root stays a readable sequence
/// of registrations and pipeline steps instead of also carrying its helpers.
/// Pure move: same code, same callers, same order.
/// </remarks>
internal static class HostBootstrap
{
    internal static string? ParseDatabaseName(string? connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            return null;
        }
        foreach (var part in connectionString.Split(';'))
        {
            var kv = part.Split(new[] { '=' }, 2, StringSplitOptions.TrimEntries);
            if (kv.Length != 2)
            {
                continue;
            }
            if (string.Equals(kv[0], "database", StringComparison.OrdinalIgnoreCase)
                || string.Equals(kv[0], "db", StringComparison.OrdinalIgnoreCase))
            {
                return string.IsNullOrWhiteSpace(kv[1]) ? null : kv[1];
            }
        }
        return null;
    }

    internal static async Task RepairMetricsExportSecretAsync(WebApplication app)
    {
        var secret = await Console.In.ReadToEndAsync();
        secret = secret.TrimEnd('\r', '\n');
        if (string.IsNullOrWhiteSpace(secret))
        {
            throw new InvalidOperationException(
                "The metrics export secret must be supplied through standard input.");
        }

        using var scope = app.Services.CreateScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var configuration = await database.IdentityMetricsConfigurations
            .SingleOrDefaultAsync(item =>
                item.Id == Sufficit.Identity.Core.Entities.IdentityMetricsConfiguration.SingletonId);
        if (configuration is null)
        {
            throw new InvalidOperationException(
                "The identity metrics configuration row does not exist.");
        }

        if (!configuration.ExportEnabled
            || !string.Equals(configuration.Provider, "victoria_metrics",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "External VictoriaMetrics export is not enabled in the current configuration.");
        }

        var keyVault = scope.ServiceProvider.GetRequiredService<IKeyVault>();
        var key = await keyVault.RotateKeyAsync("identity-metrics-export");
        configuration.SecretCiphertext = await keyVault.EncryptAsync(
            "identity-metrics-export",
            secret,
            new Dictionary<string, string> { ["configuration"] = "identity-metrics" });
        configuration.UpdatedAtUtc = DateTime.UtcNow;
        await database.SaveChangesAsync();

        app.Logger.LogInformation(
            "Repaired the Identity metrics export credential using vault key version {Version}; plaintext was not logged.",
            key.Version);
        Console.WriteLine($"metrics_export_secret_repaired key_version={key.Version}");
    }

    internal static async Task ApplyMigrationsWithAdvisoryLockAsync(
        AppDbContext database)
    {
        var provider = database.Database.ProviderName ?? string.Empty;
        if (!provider.Contains("MySql", StringComparison.OrdinalIgnoreCase))
        {
            await database.Database.MigrateAsync();
            return;
        }

        var connection = database.Database.GetDbConnection();
        await connection.OpenAsync();
        try
        {
            await using var acquire = connection.CreateCommand();
            acquire.CommandText =
                "SELECT GET_LOCK('sufficit_identity_schema_migrator', 60);";
            var acquired = Convert.ToInt32(
                await acquire.ExecuteScalarAsync(),
                System.Globalization.CultureInfo.InvariantCulture);
            if (acquired != 1)
            {
                throw new InvalidOperationException(
                    "Unable to acquire the Sufficit Identity schema migration lock.");
            }

            try
            {
                await database.Database.MigrateAsync();
            }
            finally
            {
                await using var release = connection.CreateCommand();
                release.CommandText =
                    "SELECT RELEASE_LOCK('sufficit_identity_schema_migrator');";
                await release.ExecuteScalarAsync();
            }
        }
        finally
        {
            await connection.CloseAsync();
        }
    }
}
