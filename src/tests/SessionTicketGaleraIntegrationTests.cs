using System.Data.Common;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using MySqlConnector;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class SessionTicketGaleraIntegrationTests
{
    public sealed class OwnedGaleraFactAttribute : FactAttribute
    {
        public OwnedGaleraFactAttribute()
        {
            if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("IDENTITY_TEST_OWNED_GALERA_CONNECTIONS")))
                Skip = "Run scripts/check-galera-causal-reads.py --identity-tests against its owned local cluster.";
        }
    }

    [OwnedGaleraFact]
    [Trait("Category", "GaleraIntegration")]
    public async Task Delayed_apply_exposes_revoked_ticket_without_select_barrier_but_causal_cold_read_fails_closed()
    {
        var endpoints = Environment.GetEnvironmentVariable("IDENTITY_TEST_OWNED_GALERA_CONNECTIONS")!.Split('|');
        Assert.Equal(2, endpoints.Length);
        foreach (var endpoint in endpoints)
            Assert.Equal("127.0.0.1", new MySqlConnectionStringBuilder(endpoint).Server);
        var name = "identity_session_probe_" + Guid.NewGuid().ToString("N");
        await using var admin = new MySqlConnection(endpoints[0]);
        await admin.OpenAsync();
        await Execute(admin, $"CREATE DATABASE `{name}`");
        await using var blocker = new MySqlConnection(endpoints[1]);
        await blocker.OpenAsync();
        try
        {
            ServiceProvider Services(int node, bool barrier)
            {
                var services = new ServiceCollection();
                var connection = new MySqlConnectionStringBuilder(endpoints[node]) { Database = name }.ConnectionString;
                services.AddDbContextFactory<AppDbContext>(o =>
                {
                    o.UseMySql(connection, new MariaDbServerVersion(new Version(10, 4, 34)));
                    o.UseOpenIddict();
                    if (barrier) o.AddInterceptors(new Sufficit.Identity.STS.Diagnostics.DatabaseCausalReadInterceptor());
                });
                services.AddDistributedMemoryCache();
                return services.BuildServiceProvider();
            }
            using var writerServices = Services(0, false);
            using var staleServices = Services(1, false);
            using var causalServices = Services(1, true);
            var factory = writerServices.GetRequiredService<IDbContextFactory<AppDbContext>>();
            await using (var db = await factory.CreateDbContextAsync()) await db.Database.EnsureCreatedAsync();
            OidcUserSessionRepository Repository(ServiceProvider services) =>
                new(services.GetRequiredService<IDbContextFactory<AppDbContext>>());
            var protection = new EphemeralDataProtectionProvider();
            OidcUserSessionTicketStore Store(ServiceProvider services) => new(Repository(services), protection,
                services.GetRequiredService<IDistributedCache>(), new HttpContextAccessor(),
                new SufficitIdentityOptions { UserSessions = new() { CacheLifetimeSeconds = 300 } },
                TimeProvider.System, NullLogger<OidcUserSessionTicketStore>.Instance);
            var writer = Store(writerServices);
            var stale = Store(staleServices);
            var causal = Store(causalServices);
            var ticket = new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim("sub", "galera-user"), new Claim("sid", "galera-session")], "test")),
                new AuthenticationProperties { ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1) }, "test");
            // Match the newly observed production session defaults and ensure
            // opt-in setup changes only its connection, not other clients/globals.
            using (var inherited = staleServices.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext())
            {
                inherited.Database.OpenConnection();
                using var check = inherited.Database.GetDbConnection().CreateCommand();
                check.CommandText = "SELECT @@SESSION.wsrep_dirty_reads";
                Assert.Equal(1, Convert.ToInt32(check.ExecuteScalar()));
            }
            // Exercise the synchronous EF open path as well as repository async opens.
            using (var sync = causalServices.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext())
            {
                sync.Database.OpenConnection();
                using var check = sync.Database.GetDbConnection().CreateCommand();
                check.CommandText = "SELECT @@SESSION.wsrep_sync_wait";
                Assert.Equal(15, Convert.ToInt32(check.ExecuteScalar()));
                check.CommandText = "SELECT @@SESSION.wsrep_dirty_reads";
                Assert.Equal(0, Convert.ToInt32(check.ExecuteScalar()));
                check.CommandText = "SELECT @@GLOBAL.wsrep_dirty_reads";
                Assert.Equal(1, Convert.ToInt32(check.ExecuteScalar()));
            }
            var sid = await writer.StoreAsync(ticket);
            Assert.NotNull(await Repository(causalServices).FindAsync(sid, default));
            await Execute(blocker, "SET SESSION wsrep_sync_wait=0; SET GLOBAL wsrep_desync=ON; FLUSH TABLES WITH READ LOCK;");
            await writer.RemoveAsync(sid);
            Assert.Null(await Repository(writerServices).FindAsync(sid, default));
            Assert.NotNull(await Repository(staleServices).FindAsync(sid, default));
            Assert.NotNull(await stale.RetrieveAsync(sid));
            Assert.NotNull(await staleServices.GetRequiredService<IDistributedCache>().GetAsync("identity:oidc-session:v1:" + sid));
            var error = await Record.ExceptionAsync(() => causal.RetrieveAsync(sid));
            Assert.NotNull(error);
            Assert.Equal(1205, Assert.IsType<MySqlException>(error.GetBaseException()).Number);
            Assert.Null(await causalServices.GetRequiredService<IDistributedCache>().GetAsync("identity:oidc-session:v1:" + sid));
            await Execute(blocker, "UNLOCK TABLES; SET GLOBAL wsrep_desync=OFF;");
            Assert.Null(await causal.RetrieveAsync(sid));
            await causal.RenewAsync(sid, ticket);
            Assert.Null(await Repository(causalServices).FindAsync(sid, default));
            // A DB barrier cannot retroactively remove an already cached stale ticket.
            Assert.NotNull(await stale.RetrieveAsync(sid));
        }
        finally
        {
            await Execute(blocker, "UNLOCK TABLES; SET GLOBAL wsrep_desync=OFF;");
            await Execute(admin, $"DROP DATABASE `{name}`");
        }
    }

    [OwnedGaleraFact]
    [Trait("Category", "GaleraIntegration")]
    public async Task Pooled_logical_opens_reapply_policy_with_and_without_connector_reset()
    {
        var endpoint = Environment.GetEnvironmentVariable("IDENTITY_TEST_OWNED_GALERA_CONNECTIONS")!.Split('|')[0];
        Assert.Equal("127.0.0.1", new MySqlConnectionStringBuilder(endpoint).Server);
        foreach (var reset in new[] { true, false })
        foreach (var asynchronous in new[] { true, false })
        {
            var builder = new MySqlConnectionStringBuilder(endpoint)
            {
                Pooling = true,
                MaximumPoolSize = 1,
                ConnectionReset = reset,
                ApplicationName = "identity-owned-pool-" + Guid.NewGuid().ToString("N")
            };
            var options = new DbContextOptionsBuilder<AppDbContext>()
                .UseMySql(builder.ConnectionString, new MariaDbServerVersion(new Version(10, 4, 34)))
                .AddInterceptors(new Sufficit.Identity.STS.Diagnostics.DatabaseCausalReadInterceptor())
                .Options;
            using var poolKey = new MySqlConnection();
            try
            {
                long physicalId;
                await using (var first = new AppDbContext(options))
                {
                    // Use the actual provider connection string (including EF options)
                    // for the control and cleanup, rather than accidentally creating a second pool.
                    poolKey.ConnectionString = first.Database.GetDbConnection().ConnectionString;
                    await first.Database.OpenConnectionAsync();
                    var connection = (MySqlConnection)first.Database.GetDbConnection();
                    physicalId = await Scalar(connection, "SELECT CONNECTION_ID()");
                    Assert.Equal(15, await Scalar(connection, "SELECT @@SESSION.wsrep_sync_wait"));
                    Assert.Equal(0, await Scalar(connection, "SELECT @@SESSION.wsrep_dirty_reads"));
                    // Deliberately weaken the owned session before returning it to its pool.
                    await Execute(connection, "SET SESSION wsrep_sync_wait=14; SET SESSION wsrep_dirty_reads=ON;");
                }
                // Control: the same physical connection without EF setup is unsafe,
                // whether inherited from the pool or reset to the server defaults.
                await using (var control = new MySqlConnection(poolKey.ConnectionString))
                {
                    await control.OpenAsync();
                    Assert.Equal(physicalId, await Scalar(control, "SELECT CONNECTION_ID()"));
                    Assert.Equal(14, await Scalar(control, "SELECT @@SESSION.wsrep_sync_wait"));
                    Assert.Equal(1, await Scalar(control, "SELECT @@SESSION.wsrep_dirty_reads"));
                }
                await using var next = new AppDbContext(options);
                if (asynchronous) await next.Database.OpenConnectionAsync();
                else next.Database.OpenConnection();
                var reused = (MySqlConnection)next.Database.GetDbConnection();
                Assert.Equal(physicalId, await Scalar(reused, "SELECT CONNECTION_ID()"));
                Assert.Equal(15, await Scalar(reused, "SELECT @@SESSION.wsrep_sync_wait"));
                Assert.Equal(0, await Scalar(reused, "SELECT @@SESSION.wsrep_dirty_reads"));
                Assert.Equal(1, await Scalar(reused, "SELECT @@GLOBAL.wsrep_dirty_reads"));
            }
            finally
            {
                MySqlConnection.ClearPool(poolKey);
            }
        }
    }

    private static async Task<long> Scalar(MySqlConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.CommandTimeout = 10;
        return Convert.ToInt64(await command.ExecuteScalarAsync());
    }

    private static async Task Execute(MySqlConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.CommandTimeout = 10;
        await command.ExecuteNonQueryAsync();
    }

}
