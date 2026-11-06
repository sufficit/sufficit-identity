using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class SessionTicketRedisIntegrationTests
{
    // Opt-in: the test starts/stops only its own disposable process.
    public sealed class LocalRedisFactAttribute : FactAttribute
    {
        public LocalRedisFactAttribute()
        {
            if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("SUFFICIT_TEST_REDIS_EXECUTABLE")))
                Skip = "Set SUFFICIT_TEST_REDIS_EXECUTABLE to run the disposable local Redis rehearsal.";
        }
    }

    [LocalRedisFact]
    [Trait("Category", "RedisIntegration")]
    public Task Two_stores_fall_back_during_redis_outage_and_preserve_revocation_after_restart() =>
        RehearseRecoveryAsync(persistCache: false);

    [LocalRedisFact]
    [Trait("Category", "RedisIntegration")]
    public Task Persisted_cache_can_restore_stale_ticket_but_cannot_extend_its_original_deadline() =>
        RehearseRecoveryAsync(persistCache: true);

    private static async Task RehearseRecoveryAsync(bool persistCache)
    {
        using var redis = new LocalRedis();
        await redis.StartAsync();
        using var connection = new Microsoft.Data.Sqlite.SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();
        var services = new ServiceCollection();
        services.AddDbContextFactory<AppDbContext>(options =>
        {
            options.UseSqlite(connection);
            options.UseOpenIddict();
        });
        using var databaseServices = services.BuildServiceProvider();
        var factory = databaseServices.GetRequiredService<IDbContextFactory<AppDbContext>>();
        await using (var database = await factory.CreateDbContextAsync())
            await database.Database.EnsureCreatedAsync();
        var repository = new OidcUserSessionRepository(factory);
        using var cacheServicesA = CacheServices(redis.Port);
        using var cacheServicesB = CacheServices(redis.Port);
        var cacheA = cacheServicesA.GetRequiredService<IDistributedCache>();
        var cacheB = cacheServicesB.GetRequiredService<IDistributedCache>();
        var protection = new EphemeralDataProtectionProvider();
        var cacheLifetimeSeconds = persistCache ? 15 : 5;
        OidcUserSessionTicketStore Store(IDistributedCache cache) => new(repository, protection, cache,
            new HttpContextAccessor(), new SufficitIdentityOptions
            {
                UserSessions = new() { CacheOperationTimeoutMilliseconds = 100, CacheLifetimeSeconds = cacheLifetimeSeconds },
            }, TimeProvider.System, NullLogger<OidcUserSessionTicketStore>.Instance);
        var writer = Store(cacheA);
        var reader = Store(cacheB);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "test-user"), new Claim("sid", "redis-session")], "test")),
            new AuthenticationProperties { ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1) }, "test");

        var publicationStarted = DateTimeOffset.UtcNow;
        var sid = await writer.StoreAsync(ticket);
        // Check the actual provider, so DB fallback cannot disguise a broken setup.
        var savedTicket = await cacheB.GetAsync(Key(sid));
        Assert.NotNull(savedTicket);
        Assert.NotNull(await reader.RetrieveAsync(sid));

        if (persistCache) await redis.SaveSnapshotAsync();

        redis.Stop();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        Assert.NotNull(await reader.RetrieveAsync(sid, deadline.Token));
        ticket.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddHours(2);
        await writer.RenewAsync(sid, ticket, deadline.Token);
        var renewed = (await repository.FindAsync(sid, deadline.Token))!;
        Assert.Equal(ticket.Properties.ExpiresUtc.Value.UtcDateTime, renewed.ExpiresUtc);
        await reader.RemoveAsync(sid, deadline.Token);
        Assert.Null(await repository.FindAsync(sid, deadline.Token));
        Assert.Null(await writer.RetrieveAsync(sid, deadline.Token));

        await redis.StartAsync();
        // A fresh independent client models another replica reconnecting.
        using var cacheServicesC = CacheServices(redis.Port);
        var cacheC = cacheServicesC.GetRequiredService<IDistributedCache>();
        await cacheC.SetStringAsync("recovered", "yes");
        Assert.Equal("yes", await cacheC.GetStringAsync("recovered"));
        var recovered = Store(cacheC);
        if (persistCache)
        {
            // Prove the stale RDB entry was actually restored before checking
            // its bound; an empty-cache restart must not satisfy this test.
            Assert.Equal(savedTicket, await cacheC.GetAsync(Key(sid)));
            Assert.NotNull(await recovered.RetrieveAsync(sid));
            Assert.Null(await repository.FindAsync(sid, default));

            // Read repeatedly: neither restart nor cache hits may reset expiry.
            // Allow 250 ms for scheduling/publication overhead at the boundary.
            var expiryCheck = publicationStarted.AddSeconds(cacheLifetimeSeconds).AddMilliseconds(250);
            await recovered.RetrieveAsync(sid);
            await recovered.RetrieveAsync(sid);
            var remaining = expiryCheck - DateTimeOffset.UtcNow;
            if (remaining > TimeSpan.Zero) await Task.Delay(remaining);
        }
        Assert.Null(await recovered.RetrieveAsync(sid));
        await writer.RenewAsync(sid, ticket); // Absent row must not be republished.
        Assert.Null(await cacheC.GetAsync(Key(sid)));

        // A new sign-in remains usable after cache recovery.
        ticket.Principal.Identities.First().RemoveClaim(ticket.Principal.FindFirst("sid")!);
        ticket.Principal.Identities.First().AddClaim(new Claim("sid", "new-session"));
        var freshSid = await recovered.StoreAsync(ticket);
        Assert.NotNull(await cacheC.GetAsync(Key(freshSid)));
        Assert.NotNull(await recovered.RetrieveAsync(freshSid));
    }

    private static string Key(string sid) => "identity:oidc-session:v1:" + sid;

    internal static ServiceProvider CacheServices(int port)
    {
        var services = new ServiceCollection();
        services.AddStackExchangeRedisCache(options =>
            options.Configuration = $"127.0.0.1:{port},abortConnect=false,connectTimeout=300,syncTimeout=300,asyncTimeout=300");
        return services.BuildServiceProvider();
    }

    internal sealed class LocalRedis : IDisposable
    {
        private Process? _process;
        private readonly string _directory = Path.Combine(Path.GetTempPath(), "identity-redis-" + Guid.NewGuid().ToString("N"));
        public int Port { get; }

        public LocalRedis()
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            Directory.CreateDirectory(_directory);
        }

        public async Task StartAsync()
        {
            var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("SUFFICIT_TEST_REDIS_EXECUTABLE")!)
            {
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
            };
            foreach (var argument in new[] { "--bind", "127.0.0.1", "--port", Port.ToString(),
                "--save", "", "--appendonly", "no", "--dir", _directory, "--daemonize", "no" })
                start.ArgumentList.Add(argument);
            var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _process = new Process { StartInfo = start, EnableRaisingEvents = true };
            _process.OutputDataReceived += (_, e) =>
            {
                if (e.Data?.Contains("Ready to accept connections", StringComparison.OrdinalIgnoreCase) == true)
                    ready.TrySetResult();
            };
            _process.Exited += (_, _) => ready.TrySetException(
                new InvalidOperationException("Disposable Redis exited before readiness."));
            _process.Start();
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(15));
        }

        public async Task SaveSnapshotAsync()
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, Port, timeout.Token);
            await using var stream = client.GetStream();
            // Synchronous SAVE returns only after the RDB snapshot is durable.
            await stream.WriteAsync("*1\r\n$4\r\nSAVE\r\n"u8.ToArray(), timeout.Token);
            var response = new byte[5];
            await stream.ReadExactlyAsync(response, timeout.Token);
            Assert.Equal("+OK\r\n", System.Text.Encoding.ASCII.GetString(response));
            Assert.True(File.Exists(Path.Combine(_directory, "dump.rdb")));
        }

        public void Stop()
        {
            if (_process is null) return;
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
                _process.WaitForExit(5000);
            }
            _process.Dispose();
            _process = null;
        }

        public void Dispose()
        {
            Stop();
            Directory.Delete(_directory, recursive: true);
        }
    }
}
