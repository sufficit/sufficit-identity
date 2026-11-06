using System.Net;
using System.Security.Claims;
using System.Threading.Channels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using StackExchange.Redis;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class SessionTicketRedisIntegrationTests
{
    [LocalRedisFact]
    public async Task Cluster_elects_replica_and_existing_client_discovers_owner_without_restoring_revoked_session()
    {
        var nodes = Enumerable.Range(0, 6).Select(_ => new LocalRedis(cluster: true)).ToArray();
        var connections = new List<ConnectionMultiplexer>();
        try
        {
            foreach (var node in nodes) await node.StartAsync();
            foreach (var node in nodes)
                connections.Add(await ConnectionMultiplexer.ConnectAsync($"127.0.0.1:{node.Port},allowAdmin=true,abortConnect=false,connectTimeout=3000"));
            IServer Server(int i) => connections[i].GetServer("127.0.0.1", nodes[i].Port);
            var ids = new string[6];
            for (var i = 0; i < 6; i++) ids[i] = (string)(await Server(i).ExecuteAsync("CLUSTER", "MYID"))!;
            for (var i = 0; i < 3; i++)
                await Server(i).ExecuteAsync("CLUSTER", "ADDSLOTSRANGE", i * 16384 / 3, (i + 1) * 16384 / 3 - 1);
            for (var i = 1; i < 6; i++)
                await Server(i).ExecuteAsync("CLUSTER", "MEET", "127.0.0.1", nodes[0].Port, nodes[0].BusPort);
            await Task.WhenAll(nodes.Select(n => n.WaitForLogAsync("Cluster state changed: ok")));
            for (var i = 3; i < 6; i++) await Server(i).ExecuteAsync("CLUSTER", "REPLICATE", ids[i - 3]);
            await Task.WhenAll(nodes.Skip(3).Select(n => n.WaitForLogAsync("sync: Finished with success")));

            var endpoints = string.Join(',', nodes.Select(n => $"127.0.0.1:{n.Port}"));
            using var client = await ConnectionMultiplexer.ConnectAsync(endpoints + ",abortConnect=false,connectTimeout=3000,asyncTimeout=3000");
            var changes = Channel.CreateUnbounded<bool>();
            client.ConfigurationChanged += (_, _) => changes.Writer.TryWrite(true);
            client.ConfigurationChangedBroadcast += (_, _) => changes.Writer.TryWrite(true);
            var services = new ServiceCollection();
            services.AddStackExchangeRedisCache(o => o.ConnectionMultiplexerFactory = () => Task.FromResult<IConnectionMultiplexer>(client));
            using var caches = services.BuildServiceProvider();
            var cache = caches.GetRequiredService<IDistributedCache>();
            using var sqlite = new Microsoft.Data.Sqlite.SqliteConnection("DataSource=:memory:");
            await sqlite.OpenAsync();
            var persistence = new ServiceCollection();
            persistence.AddDbContextFactory<AppDbContext>(o => { o.UseSqlite(sqlite); o.UseOpenIddict(); });
            using var provider = persistence.BuildServiceProvider();
            var factory = provider.GetRequiredService<IDbContextFactory<AppDbContext>>();
            await using (var database = await factory.CreateDbContextAsync()) await database.Database.EnsureCreatedAsync();
            var repository = new OidcUserSessionRepository(factory);
            var store = new OidcUserSessionTicketStore(repository, new EphemeralDataProtectionProvider(), cache,
                new HttpContextAccessor(), new SufficitIdentityOptions { UserSessions = new() { CacheLifetimeSeconds = 180 } },
                TimeProvider.System, NullLogger<OidcUserSessionTicketStore>.Instance);
            AuthenticationTicket Ticket(string sid) => new(new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim("sub", "cluster-test-user"), new Claim("sid", sid)], "test")),
                new AuthenticationProperties { ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1) }, "test");
            var ticket = Ticket("{cluster-rehearsal}:revoked");
            var sid = await store.StoreAsync(ticket);
            var survivor = await store.StoreAsync(Ticket("{cluster-rehearsal}:survivor"));
            Assert.NotNull(await cache.GetAsync(Key(sid)));
            var owner = (IPEndPoint)(await client.GetDatabase().IdentifyEndpointAsync(Key(sid), CommandFlags.DemandMaster))!;
            var primary = Array.FindIndex(nodes, n => n.Port == owner.Port);
            Assert.InRange(primary, 0, 2);
            await store.RemoveAsync(sid);
            Assert.Null(await repository.FindAsync(sid, default));
            // Same hash tag as both session keys; this connection's WAIT barrier
            // acknowledges the primary stream after both creation and deletion.
            Assert.Equal(new[] { "+OK", ":1" }, await nodes[primary].CommandsAsync(
                "SET {cluster-rehearsal}:barrier revoked", "WAIT 1 5000"));
            nodes[primary].Stop();
            await nodes[primary + 3].WaitForLogAsync("Failover election won");
            // Allow the client's normal periodic topology refresh; do not force ConfigureAsync.
            using var discoveryTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            while (client.GetServer("127.0.0.1", nodes[primary + 3].Port).IsReplica)
                await changes.Reader.ReadAsync(discoveryTimeout.Token);
            Assert.Equal(nodes[primary + 3].Port,
                ((IPEndPoint)(await client.GetDatabase().IdentifyEndpointAsync(Key(sid), CommandFlags.DemandMaster))!).Port);
            Assert.Null(await cache.GetAsync(Key(sid)));
            Assert.Null(await store.RetrieveAsync(sid));
            await store.RenewAsync(sid, ticket);
            Assert.Null(await repository.FindAsync(sid, default));
            Assert.Null(await cache.GetAsync(Key(sid)));
            Assert.NotNull(await cache.GetAsync(Key(survivor)));
            Assert.NotNull(await store.RetrieveAsync(survivor));
            var fresh = await store.StoreAsync(Ticket("{cluster-rehearsal}:fresh"));
            Assert.NotNull(await cache.GetAsync(Key(fresh)));
            Assert.NotNull(await store.RetrieveAsync(fresh));
        }
        finally
        {
            foreach (var connection in connections) connection.Dispose();
            foreach (var node in nodes) node.Dispose();
        }
    }
}
