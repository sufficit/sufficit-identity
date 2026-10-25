using System.Security.Claims;
using Microsoft.Data.Sqlite;
using MySqlConnector;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Maintenance;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Maintenance;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Tokens;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class TokenMaintenanceTests
{
    [Fact]
    public async Task Disabled_schedule_does_nothing_and_completed_runs_obey_schedule()
    {
        await using var h = await Harness.Create();
        await using var db = h.Db();
        Assert.Null(await TokenMaintenanceCoordinator.TryAcquireAsync(db, "a", default));
        var job = await db.Set<TokenMaintenance>().SingleAsync();
        job.Enabled = true;
        await db.SaveChangesAsync();
        await h.Worker().RunScheduledAsync(default);
        db.ChangeTracker.Clear();
        var run = await db.Set<TokenMaintenanceRun>().SingleAsync();
        Assert.Equal("succeeded", run.Status);
        Assert.NotNull(run.FinishedAtUtc);
        Assert.Null(await TokenMaintenanceCoordinator.TryAcquireAsync(db, "b", default));
        Assert.Equal(1, await db.Set<TokenMaintenanceRun>().CountAsync());
    }

    [Fact]
    public async Task Expired_owner_cannot_delete_and_stale_completion_cannot_overwrite_successor()
    {
        await using var h = await Harness.Create();
        await h.Enable();
        string oldId;
        await using (var db = h.Db())
        {
            oldId = (await TokenMaintenanceCoordinator.TryAcquireAsync(db, "old", default))!.Id;
            db.Add(new OpenIddictEntityFrameworkCoreToken
            {
                Id = "dead", CreationDate = DateTime.UtcNow.AddDays(-40),
                ExpirationDate = DateTime.UtcNow.AddDays(-1), Status = "valid", Type = "access_token"
            });
            var job = await db.Set<TokenMaintenance>().SingleAsync();
            job.LeaseUntilUtc = DateTime.UtcNow.AddMinutes(-1);
            await db.SaveChangesAsync();
        }
        var pruner = new OpenIddictPruningService(h.Provider);
        await Assert.ThrowsAsync<InvalidOperationException>(() => pruner.PruneScheduledAsync(30, oldId, default));
        await using var successor = h.Db();
        var next = (await TokenMaintenanceCoordinator.TryAcquireAsync(successor, "new", default))!;
        await using (var old = h.Db()) await TokenMaintenanceCoordinator.CompleteAsync(old, oldId, "succeeded", default);
        await Assert.ThrowsAsync<InvalidOperationException>(() => pruner.PruneScheduledAsync(30, oldId, default));
        Assert.Equal(1, await successor.Set<OpenIddictEntityFrameworkCoreToken>().CountAsync());
        Assert.Equal("interrupted", (await successor.Set<TokenMaintenanceRun>().SingleAsync(x => x.Id == oldId)).Status);
        await pruner.PruneScheduledAsync(30, next.Id, default);
        successor.ChangeTracker.Clear();
        Assert.Equal(0, await successor.Set<OpenIddictEntityFrameworkCoreToken>().CountAsync());
        Assert.Equal(1, (await successor.Set<TokenMaintenanceRun>().SingleAsync(x => x.Id == next.Id)).Tokens);
    }

    [Fact]
    public async Task Stale_claim_loses_and_manual_request_survives_current_run_completion()
    {
        await using var h = await Harness.Create();
        await h.Enable();
        await using var stale = h.Db();
        await stale.Set<TokenMaintenance>().LoadAsync();
        await using var first = h.Db();
        var run = (await TokenMaintenanceCoordinator.TryAcquireAsync(first, "first", default))!;
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() =>
            TokenMaintenanceCoordinator.TryAcquireAsync(stale, "second", default));
        await using var writer = h.Db();
        var job = await writer.Set<TokenMaintenance>().SingleAsync();
        job.RunRequested = true;
        job.Revision = Guid.NewGuid().ToString("N");
        await writer.SaveChangesAsync();
        await using (var finish = h.Db()) await TokenMaintenanceCoordinator.CompleteAsync(finish, run.Id, "succeeded", default);
        await using var next = h.Db();
        Assert.NotNull(await TokenMaintenanceCoordinator.TryAcquireAsync(next, "next", default));
        Assert.Equal(2, await next.Set<TokenMaintenanceRun>().CountAsync());
    }

    [Fact]
    public async Task Management_checks_permissions_validates_audits_and_rejects_stale_edits()
    {
        await using var h = await Harness.Create();
        await using var db = h.Db();
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var evaluator = new Evaluator();
        var service = new TokenMaintenanceManagementService(db, new ManagementOperationGuard(
            evaluator, db, cache, NullLogger<ManagementOperationGuard>.Instance));
        var context = new ManagementRequestContext(new ClaimsPrincipal(new ClaimsIdentity(
            new[] { new Claim("sub", "test-operator") }, "test")), "maintenance-test");
        await Assert.ThrowsAsync<ManagementAccessException>(() => service.GetAsync(context));
        evaluator.Read = true;
        var initial = await service.GetAsync(context);
        await Assert.ThrowsAsync<ManagementAccessException>(() => service.SaveAsync(new(initial.Revision, true, 30, 360), context));
        evaluator.Write = true;
        await Assert.ThrowsAsync<ManagementValidationException>(() => service.SaveAsync(new(initial.Revision, true, 0, 360), context));
        await service.SaveAsync(new(initial.Revision, true, 20, 60), context);
        await Assert.ThrowsAsync<ManagementValidationException>(() => service.SaveAsync(new(initial.Revision, false, 20, 60), context));
        var current = await service.GetAsync(context);
        await service.RequestRunAsync(current.Revision, context);
        Assert.True((await service.GetAsync(context)).RunRequested);
        Assert.Equal(2, await db.ManagementAuditEvents.CountAsync(x => x.OperationOutcome == "succeeded"));
        Assert.Empty(await db.Set<TokenMaintenanceRun>().ToListAsync()); // HTTP only queues.
        await Assert.ThrowsAsync<InvalidOperationException>(() => new OpenIddictPruningService(h.Provider).PruneAsync(30, default));
    }

    [Fact]
    [Trait("Category", "MariaDbIntegration")]
    public async Task MariaDb_migration_and_concurrent_acquisition_are_valid()
    {
        var configured = Environment.GetEnvironmentVariable("SUFFICIT_IDENTITY_MARIADB_CONNECTION");
        if (string.IsNullOrWhiteSpace(configured))
        {
            Assert.NotEqual("true", Environment.GetEnvironmentVariable("CI"));
            return;
        }
        var name = $"identity_maintenance_{Guid.NewGuid():N}";
        var connection = new MySqlConnectionStringBuilder(configured) { Database = "", Pooling = false };
        await using var admin = new MySqlConnection(connection.ConnectionString);
        await admin.OpenAsync();
        await using var sql = admin.CreateCommand();
        sql.CommandText = $"CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin";
        await sql.ExecuteNonQueryAsync();
        try
        {
            connection.Database = name;
            var options = new DbContextOptionsBuilder<AppDbContext>().UseMySql(connection.ConnectionString,
                new MariaDbServerVersion(new Version(10, 4, 34))).UseOpenIddict().Options;
            await using var db = new AppDbContext(options);
            await db.Database.MigrateAsync();
            Assert.Empty(await db.Database.GetPendingMigrationsAsync());
            Assert.False(db.Database.HasPendingModelChanges());
            var job = await db.Set<TokenMaintenance>().SingleAsync();
            Assert.False(job.Enabled);
            job.Enabled = true;
            await db.SaveChangesAsync();
            async Task<string?> Claim(string owner)
            {
                await using var contender = new AppDbContext(options);
                try { return (await TokenMaintenanceCoordinator.TryAcquireAsync(contender, owner, default))?.Id; }
                catch (DbUpdateConcurrencyException) { return null; }
                catch (DbUpdateException e) when (e.InnerException is MySqlException { Number: 1213 }) { return null; }
            }
            var claims = await Task.WhenAll(Claim("replica-a"), Claim("replica-b"));
            var winner = Assert.Single(claims, x => x != null)!;
            Assert.Equal(1, await db.Set<TokenMaintenanceRun>().CountAsync());
            await using var scopeProvider = new ServiceCollection()
                .AddDbContext<AppDbContext>(o => o.UseMySql(connection.ConnectionString,
                    new MariaDbServerVersion(new Version(10, 4, 34))).UseOpenIddict()).BuildServiceProvider();
            var parent = new OpenIddictEntityFrameworkCoreAuthorization
            {
                Id = "old-authorization", CreationDate = DateTime.UtcNow.AddDays(-40),
                Status = "valid", Type = "ad-hoc"
            };
            db.Add(parent);
            for (var i = 0; i < 251; i++) db.Add(new OpenIddictEntityFrameworkCoreToken
            {
                Authorization = parent, CreationDate = DateTime.UtcNow.AddDays(-40),
                ExpirationDate = DateTime.UtcNow.AddDays(-1), Status = "valid", Type = "access_token"
            });
            await db.SaveChangesAsync();
            var pruner = new OpenIddictPruningService(scopeProvider);
            Assert.Equal((251L, 1L), await pruner.PruneScheduledAsync(30, winner, default));
            db.ChangeTracker.Clear();
            await TokenMaintenanceCoordinator.CompleteAsync(db, winner, "succeeded", default);
            var completed = await db.Set<TokenMaintenanceRun>().SingleAsync();
            Assert.Equal("succeeded", completed.Status);
            Assert.Equal(251, completed.Tokens);
            Assert.Equal(1, completed.Authorizations);
        }
        finally
        {
            sql.CommandText = $"DROP DATABASE `{name}`";
            await sql.ExecuteNonQueryAsync();
        }
    }

    private sealed class Evaluator : IManagementAuthorizationEvaluator
    {
        public bool Read, Write;
        public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(ClaimsPrincipal principal, string capability,
            ManagementResource resource, CancellationToken cancellationToken = default) => ValueTask.FromResult(
                (capability == ManagementCapabilities.MaintenanceRead ? Read : Write)
                    ? ManagementAuthorizationDecision.Allowed(capability)
                    : ManagementAuthorizationDecision.Denied("capability_missing", capability));
    }

    private sealed class Harness(SqliteConnection connection, ServiceProvider provider) : IAsyncDisposable
    {
        public ServiceProvider Provider => provider;
        public AppDbContext Db() => new(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).UseOpenIddict().Options);
        public OpenIddictPruningWorker Worker() => new(new TokenPruningOptions(), provider, NullLogger<OpenIddictPruningWorker>.Instance);
        public async Task Enable()
        {
            await using var db = Db();
            (await db.Set<TokenMaintenance>().SingleAsync()).Enabled = true;
            await db.SaveChangesAsync();
        }
        public static async Task<Harness> Create()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var services = new ServiceCollection();
            services.AddDbContext<AppDbContext>(o => o.UseSqlite(connection).UseOpenIddict());
            var h = new Harness(connection, services.BuildServiceProvider());
            await using var db = h.Db();
            await db.Database.EnsureCreatedAsync();
            return h;
        }
        public async ValueTask DisposeAsync() { await provider.DisposeAsync(); await connection.DisposeAsync(); }
    }
}
