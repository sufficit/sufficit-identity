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
internal static partial class HostBootstrap
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

    internal static async Task<int> VerifyVaultAsync(WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var keyVault = scope.ServiceProvider.GetRequiredService<IKeyVault>();
        var results = new[]
        {
            await VaultRestoreVerification.VerifyNamedSecretsAsync(database, keyVault),
            await Sufficit.Identity.STS.Security.SecondFactorSecretVerification.VerifyAsync(database, keyVault),
        };
        foreach (var result in results)
        {
            Console.WriteLine($"vault_verify kind={result.Kind} decrypted={result.Decrypted} failed={result.Failed.Count}");
            foreach (var id in result.Failed)
                Console.WriteLine($"vault_verify_failed kind={result.Kind} id={id}");
        }
        return results.Any(result => result.Failed.Count > 0) ? 1 : 0;
    }

    /// <summary>
    /// Plan C1: moves the vault data keys and the Data Protection key ring to
    /// the active KEK certificate, after a rotation put the old one in
    /// Sufficit:Vault:PreviousCertificatePaths. Counts and ids only; exit code
    /// 1 when anything is still under a previous KEK. Audited, kept for good.
    /// </summary>
    internal static async Task<int> RewrapVaultKekAsync(WebApplication app, string[] args)
    {
        var operationId = ArgumentValue(args, "--operation-id");
        var reason = ArgumentValue(args, "--reason");
        if (string.IsNullOrWhiteSpace(operationId) || string.IsNullOrWhiteSpace(reason))
        {
            Console.Error.WriteLine("usage: --rewrap-vault-kek --operation-id=<id> --reason=<text>");
            return 2;
        }

        var options = app.Services.GetRequiredService<VaultOptions>();
        var rewrap = app.Services.GetService<IVaultKekRewrap>()
            ?? throw new InvalidOperationException("The vault is disabled on this host.");
        var keys = await rewrap.RewrapAsync(operationId, reason);
        Console.WriteLine($"vault_kek_rewrap kind=vault_keys rewrapped={keys.Rewrapped} already_active={keys.AlreadyActive} failed={keys.Failed.Count} already_completed={keys.AlreadyCompleted.ToString().ToLowerInvariant()}");
        foreach (var id in keys.Failed)
            Console.WriteLine($"vault_kek_rewrap_failed kind=vault_keys key={id.Name}:{id.Version}");

        using var certificate = VaultKeyEncryptionCertificate.Load(options, new EnvironmentSecretStore());
        using var scope = app.Services.CreateScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var ring = await Sufficit.Identity.STS.Security.DataProtectionKeyRingRewrap.RewrapAsync(
            database,
            app.Services,
            certificate,
            app.Services.GetRequiredService<ILoggerFactory>());
        Console.WriteLine($"vault_kek_rewrap kind=data_protection rewrapped={ring.Rewrapped} already_active={ring.AlreadyActive} failed={ring.Failed.Count}");
        foreach (var id in ring.Failed)
            Console.WriteLine($"vault_kek_rewrap_failed kind=data_protection row={id}");

        var succeeded = keys.Failed.Count == 0 && ring.Failed.Count == 0;
        database.ManagementAuditEvents.Add(new Sufficit.Identity.Core.Entities.ManagementAuditEvent
        {
            OccurredAtUtc = DateTime.UtcNow,
            OperatorSubject = $"host:{Environment.MachineName}",
            Capability = "vault.kek.rewrap",
            ResourceType = "vault_kek",
            ResourceId = $"certificate:{certificate.Thumbprint}",
            AuthorizationOutcome = "allowed",
            OperationOutcome = succeeded ? "succeeded" : "failed",
            ReasonCode = "vault_kek_rewrapped",
            CorrelationId = operationId,
            AfterJson = System.Text.Json.JsonSerializer.Serialize(new
            {
                reason,
                vaultKeys = new { keys.Rewrapped, keys.AlreadyActive, failed = keys.Failed.Count },
                dataProtection = new { ring.Rewrapped, ring.AlreadyActive, failed = ring.Failed.Count },
            }),
            ExpiresAtUtc = Sufficit.Identity.Core.Entities.ManagementAuditRetention.Never,
        });
        await database.SaveChangesAsync();
        return succeeded ? 0 : 1;
    }

    private static string? ArgumentValue(string[] args, string name) =>
        args.Where(arg => arg.StartsWith(name + "=", StringComparison.Ordinal))
            .Select(arg => arg[(name.Length + 1)..])
            .LastOrDefault();

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
