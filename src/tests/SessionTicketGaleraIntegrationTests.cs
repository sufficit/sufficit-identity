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
                    if (barrier) o.AddInterceptors(new TestOnlySelectBarrier());
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

    private static async Task Execute(MySqlConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.CommandTimeout = 10;
        await command.ExecuteNonQueryAsync();
    }

    // Test-only comparison; no production policy is installed by this fixture.
    private sealed class TestOnlySelectBarrier : DbConnectionInterceptor
    {
        public override async Task ConnectionOpenedAsync(DbConnection connection, ConnectionEndEventData eventData,
            CancellationToken cancellationToken = default)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = "SET SESSION wsrep_sync_wait = @@SESSION.wsrep_sync_wait | 1";
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }
}
