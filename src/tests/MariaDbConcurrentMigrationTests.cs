using System.Data;
using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using MySqlConnector;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Server;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class MariaDbConcurrentMigrationTests
{
    [SessionTicketMariaDbOutageTests.LocalMariaDbFact]
    [Trait("Category", "MariaDbIntegration")]
    public async Task Overlapping_migrators_apply_canonical_schema_once()
    {
        await using var server = new SessionTicketMariaDbOutageTests.LocalMariaDb();
        await server.CreateAsync();
        var ownerCommands = new SchemaCommands(pause: true);
        var competitorCommands = new SchemaCommands(pause: false);
        DbContextOptions<AppDbContext> Options(SchemaCommands observer) =>
            new DbContextOptionsBuilder<AppDbContext>()
                .UseMySql(server.ConnectionString, new MariaDbServerVersion(new Version(10, 11)),
                    mysql => mysql.MigrationsHistoryTable(IdentityDatabaseSchema.MigrationsHistoryTable))
                .AddInterceptors(observer).Options;
        await using var owner = new AppDbContext(Options(ownerCommands));
        await using var competitor = new AppDbContext(Options(competitorCommands));
        var first = HostBootstrap.ApplyMigrationsWithAdvisoryLockAsync(owner);
        Task? second = null;
        try
        {
            await ownerCommands.Entered.Task.WaitAsync(TimeSpan.FromSeconds(30));
            second = HostBootstrap.ApplyMigrationsWithAdvisoryLockAsync(competitor);
            // Both host-wrapper invocations now overlap; owner is paused with its lock held.
            Assert.False(first.IsCompleted);
            ownerCommands.Release.TrySetResult();
            await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(60));
        }
        finally
        {
            ownerCommands.Release.TrySetResult();
            // Drain owned work before disposing contexts or removing the container.
            await Task.WhenAll(second is null ? new[] { first } : new[] { first, second });
        }
        Assert.Equal(ConnectionState.Closed, owner.Database.GetDbConnection().State);
        Assert.Equal(ConnectionState.Closed, competitor.Database.GetDbConnection().State);
        Assert.True(ownerCommands.SchemaWrites > 0);
        Assert.Equal(0, competitorCommands.SchemaWrites);
        var expected = owner.Database.GetMigrations().ToArray();
        Assert.Equal(expected, (await owner.Database.GetAppliedMigrationsAsync()).ToArray());
        Assert.Equal(expected, (await competitor.Database.GetAppliedMigrationsAsync()).ToArray());
        Assert.Empty(await competitor.Database.GetPendingMigrationsAsync());
        await using var inspection = new MySqlConnection(server.ConnectionString);
        await inspection.OpenAsync();
        await using var command = inspection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM tokenmaintenance WHERE id = 1 AND revision = 'initial'";
        Assert.Equal(1, Convert.ToInt32(await command.ExecuteScalarAsync()));
    }

    private sealed class SchemaCommands(bool pause) : DbCommandInterceptor
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int SchemaWrites { get; private set; }

        public override async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command, CommandEventData eventData, InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            var sql = command.CommandText.TrimStart();
            if (sql.StartsWith("CREATE TABLE", StringComparison.OrdinalIgnoreCase)
                || sql.StartsWith("ALTER TABLE", StringComparison.OrdinalIgnoreCase)
                || sql.StartsWith("DROP TABLE", StringComparison.OrdinalIgnoreCase))
            {
                // History table bootstrap is allowed for either migrator; count model DDL only.
                if (!sql.Contains(IdentityDatabaseSchema.MigrationsHistoryTable, StringComparison.Ordinal))
                {
                    SchemaWrites++;
                    if (pause && SchemaWrites == 1)
                    {
                        Entered.TrySetResult();
                        await Release.Task.WaitAsync(TimeSpan.FromSeconds(30), cancellationToken);
                    }
                }
            }
            return result;
        }
    }
}
