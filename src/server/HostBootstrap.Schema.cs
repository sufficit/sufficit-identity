using Sufficit.Identity.Core.Networking;
using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sufficit.Identity.Application.Branding;
using Sufficit.Identity.Core.Branding;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Server;
using Sufficit.Identity.Scim;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Mtls;
using Sufficit.Identity.UI.Abstractions.Hosting;
using Sufficit.Identity.UI;
using Sufficit.Identity.UI.Management;
using Sufficit.Identity.UI.Vault;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.Server;

internal static partial class HostBootstrap
{
    /// <summary>
    /// Dev/test applies pending EF migrations to exercise migration paths.
    /// Outside Development, only the dedicated --migrate-only process may
    /// change schema; the HTTP process rejects the legacy AutoMigrate switch.
    /// </summary>
    public static async Task ProvisionSchemaAsync(
        WebApplication app,
        SufficitIdentityOptions identityOptions,
        EnvironmentSecretStore startupSecretStore,
        bool migrateOnly)
    {
        // Dev/test applies pending EF migrations to exercise migration paths. Outside
        // Development, only the dedicated --migrate-only process may change schema;
        // the HTTP process rejects the legacy AutoMigrate switch.
        if (!app.Environment.IsDevelopment()
            && identityOptions.Database.AutoMigrate
            && !migrateOnly)
        {
            throw new InvalidOperationException(
                "Database:AutoMigrate is no longer supported by the production web process. Run Sufficit.Identity.Server.dll --migrate-only as a dedicated deployment job.");
        }

        var shouldMigrate = migrateOnly || app.Environment.IsDevelopment();
        if (shouldMigrate)
        {
            using var scope = app.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

            if (identityOptions.Database.AllowedDatabaseNames.Length > 0)
            {
                var configured = startupSecretStore.GetSecretAsync(
                        "database/connection-string")
                    .GetAwaiter()
                    .GetResult();
                var actualName = HostBootstrap.ParseDatabaseName(configured);
                if (actualName is null || !identityOptions.Database.AllowedDatabaseNames.Contains(
                        actualName, StringComparer.Ordinal))
                {
                    throw new InvalidOperationException(
                        $"Automatic database migration is enabled, but the connection string's database " +
                        $"'{actualName ?? "<unparsed>"}' is not in " +
                        $"Sufficit:Identity:Database:AllowedDatabaseNames " +
                        $"([{string.Join(", ", identityOptions.Database.AllowedDatabaseNames)}]). " +
                        "This guard prevents migrating the wrong database. Either add the database name to the " +
                        "allow-list, or disable Sufficit:Identity:Database:AutoMigrate and provision schema " +
                        "from docs/migration/sql/* instead.");
                }
            }

            await HostBootstrap.ApplyMigrationsWithAdvisoryLockAsync(db);
            app.Logger.LogInformation(
                "Applied pending database migrations (environment: {Environment}, dedicatedMigrator: {DedicatedMigrator}).",
                app.Environment.EnvironmentName,
                migrateOnly);
        }
    }
}
