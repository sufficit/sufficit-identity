using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Server;
using Sufficit.Identity.STS;
using Sufficit.Identity.Vault;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class SchemaProvisioningGuardTests
{
    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public async Task Http_auto_migrate_is_rejected_before_database_resolution(string environment)
    {
        var accesses = 0;
        await using var app = App(environment, () => accesses++);
        var options = new SufficitIdentityOptions { Database = new() { AutoMigrate = true } };
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            HostBootstrap.ProvisionSchemaAsync(app, options, new EnvironmentSecretStore(), migrateOnly: false));
        Assert.Contains("--migrate-only", error.Message);
        Assert.Equal(0, accesses);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public async Task Http_without_auto_migrate_does_not_access_database(string environment)
    {
        var accesses = 0;
        await using var app = App(environment, () => accesses++);
        await HostBootstrap.ProvisionSchemaAsync(app, new SufficitIdentityOptions(),
            new EnvironmentSecretStore(), migrateOnly: false);
        Assert.Equal(0, accesses);
    }

    [Theory]
    [InlineData("Production", true, true)]
    [InlineData("Production", false, true)]
    [InlineData("Staging", true, true)]
    [InlineData("Development", false, false)]
    [InlineData("Development", true, false)]
    public async Task Explicit_migrator_or_development_reaches_database_boundary(
        string environment, bool autoMigrate, bool migrateOnly)
    {
        var accesses = 0;
        await using var app = App(environment, () => accesses++);
        var options = new SufficitIdentityOptions { Database = new() { AutoMigrate = autoMigrate } };
        // Stop at resolution, before any connection, secret lookup or schema mutation.
        await Assert.ThrowsAsync<DatabaseBoundaryReached>(() =>
            HostBootstrap.ProvisionSchemaAsync(app, options, new EnvironmentSecretStore(), migrateOnly));
        Assert.Equal(1, accesses);
    }

    private static WebApplication App(string environment, Action onDatabaseAccess)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = environment,
            ApplicationName = typeof(SchemaProvisioningGuardTests).Assembly.GetName().Name,
        });
        builder.Services.AddScoped<AppDbContext>(_ =>
        {
            onDatabaseAccess();
            throw new DatabaseBoundaryReached();
        });
        return builder.Build();
    }

    private sealed class DatabaseBoundaryReached : Exception { }
}
