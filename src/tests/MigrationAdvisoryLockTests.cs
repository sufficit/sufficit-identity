using System.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using MySqlConnector;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Server;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class MigrationAdvisoryLockTests
{
    [SessionTicketMariaDbOutageTests.LocalMariaDbFact]
    [Trait("Category", "MariaDbIntegration")]
    public async Task Lock_excludes_competitor_and_is_released_after_success_and_failure()
    {
        await using var server = new SessionTicketMariaDbOutageTests.LocalMariaDb();
        await server.CreateAsync();
        await using var competitor = new MySqlConnection(server.ConnectionString);
        await competitor.OpenAsync();
        var calls = 0;
        var fail = true;
        var failure = new InvalidOperationException("Injected migration failure");
        var probe = new ProbeMigrator(async () =>
        {
            calls++;
            // A separate real connection must not enter while the wrapper owns the lock.
            Assert.Equal(0, await ScalarAsync(competitor,
                "SELECT GET_LOCK('sufficit_identity_schema_migrator', 0);"));
            if (fail) throw failure;
        });
        var services = new ServiceCollection();
        services.AddEntityFrameworkMySql();
        services.AddScoped<IMigrator>(_ => probe);
        using var provider = services.BuildServiceProvider();
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseMySql(server.ConnectionString, new MariaDbServerVersion(new Version(10, 11)))
            .UseInternalServiceProvider(provider).Options;

        await using (var first = new AppDbContext(options))
        {
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                HostBootstrap.ApplyMigrationsWithAdvisoryLockAsync(first));
            Assert.Same(failure, error);
            Assert.Equal(ConnectionState.Closed, first.Database.GetDbConnection().State);
        }
        await AssertReleasedAsync(competitor);

        // A fresh context can retry after the failure; success must also release its lock.
        fail = false;
        await using (var retry = new AppDbContext(options))
        {
            await HostBootstrap.ApplyMigrationsWithAdvisoryLockAsync(retry);
            Assert.Equal(ConnectionState.Closed, retry.Database.GetDbConnection().State);
        }
        await AssertReleasedAsync(competitor);
        Assert.Equal(2, calls);
    }

    private static async Task AssertReleasedAsync(MySqlConnection connection)
    {
        Assert.Equal(1, await ScalarAsync(connection,
            "SELECT GET_LOCK('sufficit_identity_schema_migrator', 0);"));
        Assert.Equal(1, await ScalarAsync(connection,
            "SELECT RELEASE_LOCK('sufficit_identity_schema_migrator');"));
    }

    private static async Task<int> ScalarAsync(MySqlConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt32(await command.ExecuteScalarAsync());
    }

    // Substitute only migration execution. Connections and advisory locks remain real.
    private sealed class ProbeMigrator(Func<Task> execute) : IMigrator
    {
        public Task MigrateAsync(string? targetMigration = null, CancellationToken cancellationToken = default)
            => execute();
        public void Migrate(string? targetMigration = null) => throw new NotSupportedException();
        public string GenerateScript(string? fromMigration = null, string? toMigration = null,
            MigrationsSqlGenerationOptions options = MigrationsSqlGenerationOptions.Default)
            => throw new NotSupportedException();
        public bool HasPendingModelChanges() => throw new NotSupportedException();
    }
}
