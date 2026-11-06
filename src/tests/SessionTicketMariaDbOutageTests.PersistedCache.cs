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

public sealed partial class SessionTicketMariaDbOutageTests
{
    public sealed class LocalCombinedFactAttribute : FactAttribute
    {
        public LocalCombinedFactAttribute()
        {
            if (Environment.GetEnvironmentVariable("SUFFICIT_TEST_MARIADB_DOCKER") != "1"
                || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("SUFFICIT_TEST_REDIS_EXECUTABLE")))
                Skip = "Enable both disposable MariaDB and Redis rehearsals.";
        }
    }

    [LocalCombinedFact]
    [Trait("Category", "MariaDbIntegration")]
    [Trait("Category", "RedisIntegration")]
    public async Task Restored_stale_cache_expires_while_database_is_down_and_cannot_restore_revoked_row()
    {
        await using var server = new LocalMariaDb();
        await server.CreateAsync();
        using var redis = new SessionTicketRedisIntegrationTests.LocalRedis();
        await redis.StartAsync();
        var services = new ServiceCollection();
        services.AddDbContextFactory<AppDbContext>(options =>
        {
            options.UseMySql(server.ConnectionString, new MariaDbServerVersion(new Version(10, 11)));
            options.UseOpenIddict();
        });
        using var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IDbContextFactory<AppDbContext>>();
        await using (var db = await factory.CreateDbContextAsync()) await db.Database.EnsureCreatedAsync();
        var repository = new OidcUserSessionRepository(factory);
        var protection = new EphemeralDataProtectionProvider();
        const int lifetimeSeconds = 20;
        OidcUserSessionTicketStore Store(IDistributedCache cache) => new(repository, protection,
            cache, new HttpContextAccessor(), new SufficitIdentityOptions
            {
                UserSessions = new() { CacheOperationTimeoutMilliseconds = 100, CacheLifetimeSeconds = lifetimeSeconds },
            }, TimeProvider.System, NullLogger<OidcUserSessionTicketStore>.Instance);
        using var originalCache = SessionTicketRedisIntegrationTests.CacheServices(redis.Port);
        var cache = originalCache.GetRequiredService<IDistributedCache>();
        var writer = Store(cache);
        var ticket = Ticket("restored-revoked");
        var publicationStarted = DateTimeOffset.UtcNow;
        var sid = await writer.StoreAsync(ticket);
        var saved = await cache.GetAsync(Key(sid));
        Assert.NotNull(saved);
        await redis.SaveSnapshotAsync();
        redis.Stop();
        await writer.RemoveAsync(sid);
        Assert.Null(await repository.FindAsync(sid, default));
        await server.StopAsync();
        await redis.StartAsync();

        using var restoredCache = SessionTicketRedisIntegrationTests.CacheServices(redis.Port);
        var restored = restoredCache.GetRequiredService<IDistributedCache>();
        var reader = Store(restored);
        // Require a real stale restoration: an empty restart cannot satisfy this case.
        Assert.Equal(saved, await restored.GetAsync(Key(sid)));
        Assert.NotNull(await reader.RetrieveAsync(sid));
        await AssertDatabaseUnavailableAsync(() => reader.RenewAsync(sid, ticket));
        await AssertDatabaseUnavailableAsync(() => reader.StoreAsync(Ticket("uncommitted-restored")));
        await AssertDatabaseUnavailableAsync(() => reader.RetrieveAsync("cold-restored"));
        Assert.Null(await restored.GetAsync(Key("uncommitted-restored")));
        Assert.Equal(saved, await restored.GetAsync(Key(sid)));
        Assert.NotNull(await reader.RetrieveAsync(sid));

        // Wait for the original real Redis TTL, not for asynchronous work to finish.
        var remaining = publicationStarted.AddSeconds(lifetimeSeconds).AddMilliseconds(250) - DateTimeOffset.UtcNow;
        if (remaining > TimeSpan.Zero) await Task.Delay(remaining);
        Assert.Null(await restored.GetAsync(Key(sid)));
        // After expiry, absence of the authoritative database is surfaced, not a ticket.
        await AssertDatabaseUnavailableAsync(() => reader.RetrieveAsync(sid));
        await server.RestartAsync();
        Assert.Null(await repository.FindAsync(sid, default));
        Assert.Null(await repository.FindAsync("uncommitted-restored", default));
        Assert.Null(await reader.RetrieveAsync(sid));
        await reader.RenewAsync(sid, ticket);
        Assert.Null(await repository.FindAsync(sid, default));
        Assert.Null(await restored.GetAsync(Key(sid)));
        var fresh = await reader.StoreAsync(Ticket("fresh-after-restoration"));
        Assert.NotNull(await restored.GetAsync(Key(fresh)));
        Assert.NotNull(await reader.RetrieveAsync(fresh));
    }
}
