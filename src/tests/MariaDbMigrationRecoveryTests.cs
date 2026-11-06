using System.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using MySqlConnector;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Server;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class MariaDbMigrationRecoveryTests
{
    [SessionTicketMariaDbOutageTests.LocalMariaDbFact]
    [Trait("Category", "MariaDbIntegration")]
    public async Task Partial_ddl_failure_requires_explicit_repair_before_retry()
    {
        await using var server = new SessionTicketMariaDbOutageTests.LocalMariaDb();
        await server.CreateAsync();
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseMySql(server.ConnectionString, new MariaDbServerVersion(new Version(10, 11)),
                mysql => mysql.MigrationsHistoryTable(IdentityDatabaseSchema.MigrationsHistoryTable))
            .Options;
        await using var db = new AppDbContext(options);
        var migrations = db.Database.GetMigrations().ToArray();
        Assert.Equal(IdentityDatabaseSchema.TokenMaintenanceMigrationId, migrations[^1]);
        await db.GetService<IMigrator>().MigrateAsync(migrations[^2]);
        var before = (await db.Database.GetAppliedMigrationsAsync()).ToArray();

        // This fixture-owned table collides with the SECOND CREATE TABLE in the migration.
        await db.Database.ExecuteSqlRawAsync("CREATE TABLE tokenmaintenanceruns (fixture_marker int NOT NULL)");
        var error = await Assert.ThrowsAsync<MySqlException>(() =>
            HostBootstrap.ApplyMigrationsWithAdvisoryLockAsync(db));
        Assert.Equal(1050, error.Number); // Table already exists.
        Assert.Equal(ConnectionState.Closed, db.Database.GetDbConnection().State);
        Assert.Equal(before, (await db.Database.GetAppliedMigrationsAsync()).ToArray());
        Assert.Equal(new[] { migrations[^1] }, (await db.Database.GetPendingMigrationsAsync()).ToArray());

        // MariaDB kept the first DDL despite the failed migration: blindly retrying is not repair.
        await using var inspection = new MySqlConnection(server.ConnectionString);
        await inspection.OpenAsync();
        await using var check = inspection.CreateCommand();
        check.CommandText = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'tokenmaintenance'";
        Assert.Equal(1, Convert.ToInt32(await check.ExecuteScalarAsync()));
        check.CommandText = "SELECT COUNT(*) FROM tokenmaintenance";
        Assert.Equal(0, Convert.ToInt32(await check.ExecuteScalarAsync()));
        var retryError = await Assert.ThrowsAsync<MySqlException>(() =>
            HostBootstrap.ApplyMigrationsWithAdvisoryLockAsync(db));
        Assert.Equal(1050, retryError.Number);
        Assert.Equal(before, (await db.Database.GetAppliedMigrationsAsync()).ToArray());

        // Explicit repair is safe only here: both tables belong to this empty disposable fixture.
        await db.Database.ExecuteSqlRawAsync("DROP TABLE tokenmaintenance, tokenmaintenanceruns");
        await using var recovered = new AppDbContext(options);
        await HostBootstrap.ApplyMigrationsWithAdvisoryLockAsync(recovered);
        Assert.Equal(migrations, (await recovered.Database.GetAppliedMigrationsAsync()).ToArray());
        Assert.Empty(await recovered.Database.GetPendingMigrationsAsync());
        check.CommandText = "SELECT COUNT(*) FROM tokenmaintenance WHERE id = 1 AND enabled = 0 AND revision = 'initial'";
        Assert.Equal(1, Convert.ToInt32(await check.ExecuteScalarAsync()));
        // Completed history makes a subsequent invocation a no-op, preserving the seeded row.
        await HostBootstrap.ApplyMigrationsWithAdvisoryLockAsync(recovered);
        Assert.Equal(migrations, (await recovered.Database.GetAppliedMigrationsAsync()).ToArray());
        Assert.Equal(1, Convert.ToInt32(await check.ExecuteScalarAsync()));
    }
}
