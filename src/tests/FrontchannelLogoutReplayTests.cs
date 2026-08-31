using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.STS.Logout;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// The front-channel logout context is single-use: consuming it must log the
/// user out of every RP exactly once.
/// </summary>
/// <remarks>
/// Giving the context a database primary (eval 2026-08-30, F-4) left the
/// distributed cache as a read fallback, which reintroduced the replay in
/// exactly the multi-replica deployment the change existed to fix. The replica
/// that PREPARED the context keeps a copy in its process-local cache; once
/// another replica consumed and deleted the durable row, a browser landing back
/// on the first replica read the stale cached copy and fanned the logout out a
/// second time. The durable store is now authoritative whenever it is
/// registered, and this test pins that: a context present only in the cache is
/// not served.
/// </remarks>
[Collection(StsCollection.Name)]
public sealed class FrontchannelLogoutReplayTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public FrontchannelLogoutReplayTests(SufficitIdentityTestFactory factory)
        => _factory = factory;

    [Fact]
    public async Task Cache_only_context_is_not_served_when_the_durable_store_is_registered()
    {
        using var scope = _factory.Services.CreateScope();
        var dispatcher = scope.ServiceProvider
            .GetRequiredService<IFrontchannelLogoutDispatcher>();
        var cache = _factory.Services.GetRequiredService<IDistributedCache>();

        // Stand in for the stale copy the preparing replica keeps: a context
        // that exists in the cache and NOT in the durable store.
        const string contextId = "replay-probe-context-id";
        await cache.SetStringAsync(
            FrontchannelLogoutDispatcher.CacheKeyPrefix + contextId,
            JsonSerializer.Serialize(new[] { "https://rp.example.invalid/logout" }),
            new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(2),
            });

        var consumed = await dispatcher.ConsumeAsync(contextId, CancellationToken.None);

        Assert.Empty(consumed);
    }

    [Fact]
    public async Task Unknown_context_yields_no_logout_targets()
    {
        using var scope = _factory.Services.CreateScope();
        var dispatcher = scope.ServiceProvider
            .GetRequiredService<IFrontchannelLogoutDispatcher>();

        Assert.Empty(await dispatcher.ConsumeAsync(
            "never-issued",
            CancellationToken.None));
    }
}
