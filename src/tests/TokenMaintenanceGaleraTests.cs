using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using MySqlConnector;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Maintenance;
using Sufficit.Identity.STS.Tokens;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class TokenMaintenanceGaleraTests
{
    [Fact]
    [Trait("Category", "GaleraIntegration")]
    public async Task Distinct_writers_certify_one_claim_and_fence_the_expired_executor()
    {
        var configured = Environment.GetEnvironmentVariable("IDENTITY_TEST_GALERA_CONNECTIONS");
        if (string.IsNullOrWhiteSpace(configured)) return;
        var endpoints = configured.Split('|');
        Assert.True(endpoints.Length >= 2);
        var name = "identity_maintenance_galera_" + Guid.NewGuid().ToString("N");
        var connections = endpoints.Select(x => new MySqlConnectionStringBuilder(x)
            { Database = name, Pooling = false }.ConnectionString).ToArray();
        AppDbContext Db(int node) => new(new DbContextOptionsBuilder<AppDbContext>().UseMySql(connections[node],
            new MariaDbServerVersion(new Version(10, 4, 34))).UseOpenIddict().Options);
        await using var admin = new MySqlConnection(new MySqlConnectionStringBuilder(endpoints[0]) { Database = "" }.ConnectionString);
        await admin.OpenAsync();
        await using var sql = admin.CreateCommand();
        sql.CommandText = $"CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin";
        await sql.ExecuteNonQueryAsync();
        try
        {
            await using (var db = Db(0))
            {
                await db.Database.MigrateAsync();
                var job = await db.Set<TokenMaintenance>().SingleAsync();
                job.Enabled = true;
                await db.SaveChangesAsync();
            }
            // Both writers pre-read the identical revision before attempting
            // their claim; one local lock on each node cannot serialize this.
            for (var round = 0; round < 20; round++)
            {
                await using var a = Db(0);
                await using var b = Db(1);
                await a.Set<TokenMaintenance>().LoadAsync();
                await b.Set<TokenMaintenance>().LoadAsync();
                async Task<TokenMaintenanceRun?> Claim(AppDbContext db, string owner)
                {
                    try { return await TokenMaintenanceCoordinator.TryAcquireAsync(db, owner, default); }
                    catch (DbUpdateConcurrencyException) { return null; }
                    catch (Exception e) when (e.GetBaseException() is MySqlException { Number: 1213 }) { return null; }
                }
                var claims = await Task.WhenAll(Claim(a, "writer-a"), Claim(b, "writer-b"));
                var winner = Assert.Single(claims, x => x != null)!;
                await using var finish = Db(0);
                Assert.Equal(round + 1, await finish.Set<TokenMaintenanceRun>().CountAsync());
                await TokenMaintenanceCoordinator.CompleteAsync(finish, winner.Id, "succeeded", default);
                var job = await finish.Set<TokenMaintenance>().SingleAsync();
                job.NextRunAtUtc = DateTime.UnixEpoch;
                job.Revision = Guid.NewGuid().ToString("N");
                await finish.SaveChangesAsync();
            }
            string oldId;
            await using (var old = Db(0))
            {
                oldId = (await TokenMaintenanceCoordinator.TryAcquireAsync(old, "old-executor", default))!.Id;
                var job = await old.Set<TokenMaintenance>().SingleAsync();
                job.LeaseUntilUtc = DateTime.UtcNow.AddMinutes(-1);
                old.Add(new OpenIddictEntityFrameworkCoreToken { Id = "expired-token", CreationDate = DateTime.UtcNow.AddDays(-40),
                    ExpirationDate = DateTime.UtcNow.AddDays(-1), Status = "valid", Type = "access_token" });
                await old.SaveChangesAsync();
            }
            await using var successor = Db(1);
            var next = (await TokenMaintenanceCoordinator.TryAcquireAsync(successor, "successor", default))!;
            await using var provider = new ServiceCollection().AddDbContext<AppDbContext>(o => o.UseMySql(connections[0],
                new MariaDbServerVersion(new Version(10, 4, 34))).UseOpenIddict()).BuildServiceProvider();
            var pruner = new OpenIddictPruningService(provider);
            await Assert.ThrowsAsync<InvalidOperationException>(() => pruner.PruneScheduledAsync(30, oldId, default));
            Assert.Equal(1, await successor.Set<OpenIddictEntityFrameworkCoreToken>().CountAsync());
            Assert.Equal((1L, 0L), await pruner.PruneScheduledAsync(30, next.Id, default));
            successor.ChangeTracker.Clear();
            await TokenMaintenanceCoordinator.CompleteAsync(successor, next.Id, "succeeded", default);
            Assert.Equal("interrupted", (await successor.Set<TokenMaintenanceRun>().SingleAsync(x => x.Id == oldId)).Status);
            Assert.Empty(await successor.Set<OpenIddictEntityFrameworkCoreToken>().ToListAsync());
        }
        finally
        {
            sql.CommandText = $"DROP DATABASE `{name}`";
            await sql.ExecuteNonQueryAsync();
        }
    }
}
