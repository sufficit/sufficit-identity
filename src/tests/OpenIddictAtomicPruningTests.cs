using System.Data.Common;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MySqlConnector;
using OpenIddict.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.STS.Tokens;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

public sealed class OpenIddictAtomicPruningTests
{
    [Fact]
    public async Task Last_token_and_parent_commit_together_in_bounded_batches()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await VerifyAsync(options => options.UseSqlite(connection));
    }

    [Fact]
    [Trait("Category", "MariaDbIntegration")]
    public async Task Atomic_bounded_pruning_works_on_mariadb()
    {
        var configured = Environment.GetEnvironmentVariable("SUFFICIT_IDENTITY_MARIADB_CONNECTION");
        if (string.IsNullOrWhiteSpace(configured))
        {
            Assert.False(string.Equals(Environment.GetEnvironmentVariable("CI"), "true",
                StringComparison.OrdinalIgnoreCase), "MariaDB connection is required in CI.");
            return;
        }

        var database = $"identity_atomic_pruning_{Guid.NewGuid():N}";
        var builder = new MySqlConnectionStringBuilder(configured) { Database = "", Pooling = false };
        await using var admin = new MySqlConnection(builder.ConnectionString);
        await admin.OpenAsync();
        await using var command = admin.CreateCommand();
        command.CommandText = $"CREATE DATABASE `{database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin";
        await command.ExecuteNonQueryAsync();
        try
        {
            builder.Database = database;
            await VerifyAsync(options => options.UseMySql(builder.ConnectionString,
                new MariaDbServerVersion(new Version(10, 4, 34))));
        }
        finally
        {
            command.CommandText = $"DROP DATABASE `{database}`";
            await command.ExecuteNonQueryAsync();
        }
    }

    private static async Task VerifyAsync(Action<DbContextOptionsBuilder> configure)
    {
        var commits = new CommitCapture();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMemoryCache();
        services.AddDbContext<AppDbContext>(options =>
        {
            configure(options);
            options.UseOpenIddict().AddInterceptors(commits);
        });
        services.AddOpenIddict().AddCore(core => core.UseEntityFrameworkCore().UseDbContext<AppDbContext>());
        services.Configure<OpenIddictEntityFrameworkCoreOptions>(options => options.DisableBulkOperations = true);
        await using var provider = services.BuildServiceProvider();
        const int tokenCount = 251;
        await using (var scope = provider.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            await db.Database.EnsureCreatedAsync();
            var parent = new OpenIddictEntityFrameworkCoreAuthorization
            {
                Id = commits.AuthorizationId, CreationDate = DateTime.UtcNow.AddDays(-40),
                Status = Statuses.Valid, Type = AuthorizationTypes.AdHoc
            };
            db.Add(parent);
            for (var index = 0; index < tokenCount; index++)
                db.Add(new OpenIddictEntityFrameworkCoreToken
                {
                    Authorization = parent, CreationDate = DateTime.UtcNow.AddDays(-40),
                    ExpirationDate = DateTime.UtcNow.AddDays(-1), Status = Statuses.Valid,
                    Type = TokenTypeIdentifiers.RefreshToken
                });
            await db.SaveChangesAsync();
        }

        commits.Enabled = true;
        var result = await new OpenIddictPruningService(provider).PruneAsync(30, CancellationToken.None);
        Assert.Equal(tokenCount, result.Tokens);
        Assert.Equal(1, result.Authorizations);
        var previous = tokenCount;
        foreach (var (tokens, parents) in commits.Snapshots)
        {
            // No committed state may expose the last child deletion without
            // the parent deletion: those must belong to one writeset.
            Assert.False(tokens == 0 && parents != 0,
                "The last token and its authorization were committed separately.");
            Assert.InRange(previous - tokens, 0, 100);
            previous = tokens;
        }
        Assert.Equal(0, previous);
        Assert.True(commits.Snapshots.Count >= 3);
        Assert.Equal((0L, 0L), await new OpenIddictPruningService(provider)
            .PruneAsync(30, CancellationToken.None));

        // A failure after both deletes but before commit must restore the
        // children as well as the parent, never leave a partially pruned chain.
        commits.Enabled = false;
        await using (var scope = provider.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var parent = new OpenIddictEntityFrameworkCoreAuthorization
            {
                Id = commits.AuthorizationId, CreationDate = DateTime.UtcNow.AddDays(-40),
                Status = Statuses.Valid, Type = AuthorizationTypes.AdHoc
            };
            db.Add(parent);
            for (var index = 0; index < 9; index++)
                db.Add(new OpenIddictEntityFrameworkCoreToken
                {
                    Authorization = parent, CreationDate = DateTime.UtcNow.AddDays(-40),
                    ExpirationDate = DateTime.UtcNow.AddDays(-1), Status = Statuses.Valid,
                    Type = TokenTypeIdentifiers.RefreshToken
                });
            await db.SaveChangesAsync();
        }
        commits.Enabled = true;
        commits.RejectEmptyChain = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new OpenIddictPruningService(provider).PruneAsync(30, CancellationToken.None));
        await using (var scope = provider.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            Assert.Equal(9, await db.Set<OpenIddictEntityFrameworkCoreToken>()
                .CountAsync(token => token.Authorization!.Id == commits.AuthorizationId));
            Assert.True(await db.Set<OpenIddictEntityFrameworkCoreAuthorization>()
                .AnyAsync(parent => parent.Id == commits.AuthorizationId));
        }
    }

    private sealed class CommitCapture : DbTransactionInterceptor
    {
        public string AuthorizationId { get; } = Guid.NewGuid().ToString();
        public bool Enabled { get; set; }
        public bool RejectEmptyChain { get; set; }
        public List<(int Tokens, int Parents)> Snapshots { get; } = [];

        public override InterceptionResult TransactionCommitting(
            DbTransaction transaction, TransactionEventData eventData, InterceptionResult result)
        {
            if (!Enabled) return result;
            using var command = transaction.Connection!.CreateCommand();
            command.Transaction = transaction;
            var parameter = command.CreateParameter();
            parameter.ParameterName = "@id";
            parameter.Value = AuthorizationId;
            command.Parameters.Add(parameter);
            command.CommandText = "SELECT COUNT(*) FROM tokens WHERE authorization_id=@id";
            var tokens = Convert.ToInt32(command.ExecuteScalar());
            command.CommandText = "SELECT COUNT(*) FROM authorizations WHERE id=@id";
            Snapshots.Add((tokens, Convert.ToInt32(command.ExecuteScalar())));
            return result;
        }

        public override async ValueTask<InterceptionResult> TransactionCommittingAsync(
            DbTransaction transaction, TransactionEventData eventData, InterceptionResult result,
            CancellationToken cancellationToken = default)
        {
            if (!Enabled) return result;
            await using var command = transaction.Connection!.CreateCommand();
            command.Transaction = transaction;
            var parameter = command.CreateParameter();
            parameter.ParameterName = "@id";
            parameter.Value = AuthorizationId;
            command.Parameters.Add(parameter);
            command.CommandText = "SELECT COUNT(*) FROM tokens WHERE authorization_id=@id";
            var tokens = Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
            command.CommandText = "SELECT COUNT(*) FROM authorizations WHERE id=@id";
            var parents = Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
            Snapshots.Add((tokens, parents));
            if (RejectEmptyChain && tokens == 0 && parents == 0)
                throw new InvalidOperationException("Simulated commit failure.");
            return result;
        }
    }
}
