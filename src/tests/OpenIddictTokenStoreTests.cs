using System.Data.Common;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MySqlConnector;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.STS.Tokens;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

public sealed class OpenIddictTokenStoreTests
{
    [Fact]
    public async Task Authorization_chain_is_revoked_without_loading_tokens_or_saving_per_token()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await RunRevocationAndPruningContractAsync(options => options.UseSqlite(connection));
    }

    [Fact]
    [Trait("Category", "MariaDbIntegration")]
    public async Task Authorization_chain_update_and_pruning_work_on_mariadb()
    {
        var configured = Environment.GetEnvironmentVariable("SUFFICIT_IDENTITY_MARIADB_CONNECTION");
        if (string.IsNullOrWhiteSpace(configured))
        {
            Assert.False(string.Equals(Environment.GetEnvironmentVariable("CI"), "true",
                StringComparison.OrdinalIgnoreCase), "SUFFICIT_IDENTITY_MARIADB_CONNECTION is required in CI.");
            return;
        }

        // Never alter the configured database: create/drop only our unique,
        // disposable schema, as in the existing MariaDB grant smoke tests.
        var database = $"identity_token_store_test_{Guid.NewGuid():N}";
        var builder = new MySqlConnectionStringBuilder(configured) { Database = "", Pooling = false };
        await using var admin = new MySqlConnection(builder.ConnectionString);
        await admin.OpenAsync();
        await using var command = admin.CreateCommand();
        command.CommandText = $"CREATE DATABASE `{database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin";
        await command.ExecuteNonQueryAsync();
        try
        {
            builder.Database = database;
            await RunRevocationAndPruningContractAsync(options => options.UseMySql(
                builder.ConnectionString, new MariaDbServerVersion(new Version(10, 4, 34))));
            await VerifyMaintenanceCommandsAsync(builder.ConnectionString);
        }
        finally
        {
            command.CommandText = $"DROP DATABASE `{database}`";
            await command.ExecuteNonQueryAsync();
        }
    }

    private static async Task VerifyMaintenanceCommandsAsync(string connectionString)
    {
        var directory = Path.Combine(Path.GetTempPath(), "identity-command-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            async Task<(int Code, string Output)> Run(string command, string connection)
            {
                var dotnet = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH")
                    ?? (Environment.GetEnvironmentVariable("DOTNET_ROOT") is { } root
                        ? Path.Combine(root, "dotnet") : "dotnet");
                var start = new System.Diagnostics.ProcessStartInfo(dotnet)
                {
                    WorkingDirectory = directory,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false
                };
                start.ArgumentList.Add(typeof(Sufficit.Identity.Server.TokenPruningState).Assembly.Location);
                start.ArgumentList.Add(command);
                start.Environment["DOTNET_ENVIRONMENT"] = "Production";
                start.Environment["SUFFICIT_SECRET_DATABASE_CONNECTION_STRING"] = connection;
                start.Environment["Sufficit__Identity__TokenPruning__StatePath"] = Path.Combine(directory, "success.json");
                start.Environment["Sufficit__Identity__TokenPruning__RunInWebHost"] = "false";
                using var process = System.Diagnostics.Process.Start(start)!;
                var stdout = process.StandardOutput.ReadToEndAsync();
                var stderr = process.StandardError.ReadToEndAsync();
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                try { await process.WaitForExitAsync(deadline.Token); }
                finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }
                return (process.ExitCode, await stdout + await stderr);
            }
            var missing = await Run("--check-token-pruning", "invalid");
            Assert.Equal(1, missing.Code);
            Assert.Contains("TokenPruningOverdue", missing.Output);
            var prune = await Run("--prune-tokens", connectionString);
            Assert.True(prune.Code == 0, prune.Output);
            Assert.Contains("TokenPruningSucceeded", prune.Output);
            var healthy = await Run("--check-token-pruning", "invalid");
            Assert.True(healthy.Code == 0, healthy.Output); // Watchdog must not connect to the database.
            Assert.Contains("TokenPruningHealthy", healthy.Output);
            var path = Path.Combine(directory, "success.json");
            var previous = await File.ReadAllTextAsync(path);
            var failed = await Run("--prune-tokens", "invalid");
            Assert.Equal(1, failed.Code);
            Assert.Equal(previous, await File.ReadAllTextAsync(path));
            var stale = new Sufficit.Identity.Server.TokenPruningState(DateTimeOffset.UtcNow.AddHours(-15), 0, 0);
            await File.WriteAllTextAsync(path, System.Text.Json.JsonSerializer.Serialize(stale));
            var overdue = await Run("--check-token-pruning", "invalid");
            Assert.Equal(1, overdue.Code);
            Assert.Contains("TokenPruningOverdue", overdue.Output);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static async Task RunRevocationAndPruningContractAsync(
        Action<DbContextOptionsBuilder> configure)
    {
        var commands = new CommandCapture();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMemoryCache();
        services.AddDbContext<AppDbContext>(options =>
        {
            configure(options);
            options.UseOpenIddict().AddInterceptors(commands);
        });
        services.AddOpenIddict().AddCore(core =>
        {
            core.UseEntityFrameworkCore().UseDbContext<AppDbContext>();
            core.ReplaceTokenStore<OpenIddictEntityFrameworkCoreToken, SufficitOpenIddictTokenStore>();
        });
        services.Configure<OpenIddictEntityFrameworkCoreOptions>(options => options.DisableBulkOperations = true);
        await using var provider = services.BuildServiceProvider();

        const int chainLength = 2000;
        var authorizationId = Guid.NewGuid().ToString();
        var otherAuthorizationId = Guid.NewGuid().ToString();
        var old = DateTime.UtcNow.AddDays(-40);
        await using (var scope = provider.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            await db.Database.EnsureCreatedAsync();
            var authorization = new OpenIddictEntityFrameworkCoreAuthorization
            {
                Id = authorizationId, Status = Statuses.Valid,
                Type = AuthorizationTypes.AdHoc, CreationDate = old,
            };
            var other = new OpenIddictEntityFrameworkCoreAuthorization
            {
                Id = otherAuthorizationId, Status = Statuses.Valid,
                Type = AuthorizationTypes.AdHoc, CreationDate = old,
            };
            db.AddRange(authorization, other);
            for (var index = 0; index < chainLength; index++)
            {
                db.Add(Token(authorization, (index % 4) switch
                {
                    0 => Statuses.Valid, 1 => Statuses.Redeemed, 2 => Statuses.Inactive, _ => null,
                }));
            }
            db.Add(Token(authorization, Statuses.Revoked));
            db.Add(Token(other, Statuses.Valid));
            db.Add(Token(null, Statuses.Valid));
            await db.SaveChangesAsync();

            OpenIddictEntityFrameworkCoreToken Token(
                OpenIddictEntityFrameworkCoreAuthorization? owner, string? status) => new()
            {
                Authorization = owner, Status = status, Type = TokenTypeIdentifiers.RefreshToken,
                CreationDate = old, ExpirationDate = DateTime.UtcNow.AddDays(1),
                Payload = new string('x', 1024),
            };
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
            commands.Sql.Clear();
            Assert.Equal(chainLength, await manager.RevokeByAuthorizationIdAsync(authorizationId));
            Assert.Empty(db.ChangeTracker.Entries());
            var update = Assert.Single(commands.Sql);
            Assert.StartsWith("UPDATE", update.TrimStart(), StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("LIMIT", update, StringComparison.OrdinalIgnoreCase);
            Assert.True(scope.ServiceProvider.GetRequiredService<
                IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions>>().CurrentValue.DisableBulkOperations);
            Assert.Equal(0, await manager.RevokeByAuthorizationIdAsync(authorizationId));
            Assert.Equal(0, await manager.RevokeByAuthorizationIdAsync("missing-authorization"));
            using var canceled = new CancellationTokenSource();
            canceled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await manager.RevokeByAuthorizationIdAsync(otherAuthorizationId, canceled.Token));

            // The store participates in the caller's transaction and must not
            // flush unrelated tracked changes as a side effect of revocation.
            var pending = new OpenIddictEntityFrameworkCoreAuthorization { Status = Statuses.Valid };
            db.Add(pending);
            await using var transaction = await db.Database.BeginTransactionAsync();
            Assert.Equal(1, await manager.RevokeByAuthorizationIdAsync(otherAuthorizationId));
            Assert.Equal(EntityState.Added, db.Entry(pending).State);
            Assert.False(await db.Set<OpenIddictEntityFrameworkCoreAuthorization>()
                .AnyAsync(authorization => authorization.Id == pending.Id));
            await transaction.RollbackAsync();
        }

        // A new scope reads authoritative persisted state, just as a later
        // protocol request does. No blanket cache/change-tracker clearing.
        await using (var scope = provider.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var tokens = db.Set<OpenIddictEntityFrameworkCoreToken>();
            Assert.Equal(chainLength + 1, await tokens.CountAsync(token => token.Status == Statuses.Revoked));
            Assert.Equal(2, await tokens.CountAsync(token => token.Status == Statuses.Valid));
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
            var authorizations = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();
            var cutoff = DateTimeOffset.UtcNow.AddDays(-30);
            Assert.Equal(chainLength + 1, await manager.PruneAsync(cutoff));
            Assert.Equal(1, await authorizations.PruneAsync(cutoff));
            Assert.Equal(2, await tokens.CountAsync());
            Assert.NotNull(await authorizations.FindByIdAsync(otherAuthorizationId));
        }
    }

    private sealed class CommandCapture : DbCommandInterceptor
    {
        public List<string> Sql { get; } = [];

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command, CommandEventData eventData, InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            Sql.Add(command.CommandText);
            return ValueTask.FromResult(result);
        }

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            Sql.Add(command.CommandText);
            return ValueTask.FromResult(result);
        }
    }
}
