using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.STS.Ciba;
using Sufficit.Identity.STS.Dpop;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Tests for the IDistributedCache-backed stores (CIBA pending, DPoP nonce,
/// DPoP replay cache). These exercise the store semantics that are invisible
/// to the integration tests (which run against AddDistributedMemoryCache and
/// don't assert cross-replica behavior, but DO verify the interface contract
/// is correct for when the cache is swapped for Redis).
/// </summary>
public sealed class DistributedStoreTests
{
    private static IDistributedCache CreateCache()
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        return services.BuildServiceProvider()
            .GetRequiredService<IDistributedCache>();
    }

    // ---- CIBA pending request store ----

    [Fact]
    public async Task Ciba_store_create_find_approve_and_consume_round_trips()
    {
        var store = new DistributedCibaPendingRequestStore(CreateCache());
        var request = store.Create(
            clientId: "test-client",
            subject: "user-1",
            scopes: ["openid", "profile"],
            bindingMessage: "approve-login",
            lifetime: TimeSpan.FromMinutes(5));

        // Find returns the created request.
        var found = store.Find(request.AuthReqId);
        Assert.NotNull(found);
        Assert.Equal("test-client", found!.ClientId);
        Assert.Null(found.ApprovedSubject);

        // Approve sets the approved subject.
        Assert.True(store.Approve(request.AuthReqId, "user-1"));
        var approved = store.Find(request.AuthReqId);
        Assert.NotNull(approved);
        Assert.Equal("user-1", approved!.ApprovedSubject);

        // TryConsumeApproved returns the approved request on first call.
        Assert.True(store.TryConsumeApproved(request.AuthReqId, out var consumed));
        Assert.Equal("user-1", consumed.ApprovedSubject);

        // Second consume returns false (already consumed).
        Assert.False(store.TryConsumeApproved(request.AuthReqId, out _));

        // Find returns null after consume.
        Assert.Null(store.Find(request.AuthReqId));
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Ciba_store_deny_removes_entry()
    {
        var store = new DistributedCibaPendingRequestStore(CreateCache());
        var request = store.Create("c1", "u1", [], null, TimeSpan.FromMinutes(5));

        Assert.True(store.Deny(request.AuthReqId));
        Assert.Null(store.Find(request.AuthReqId));
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Ciba_store_try_consume_unapproved_returns_false()
    {
        var store = new DistributedCibaPendingRequestStore(CreateCache());
        var request = store.Create("c1", "u1", [], null, TimeSpan.FromMinutes(5));

        // Not approved yet → cannot consume.
        Assert.False(store.TryConsumeApproved(request.AuthReqId, out _));
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Ciba_store_deny_after_create_removes_entry()
    {
        var store = new DistributedCibaPendingRequestStore(CreateCache());
        var request = store.Create("c1", "u1", [], null, TimeSpan.FromMinutes(5));

        // Deny removes the entry and its consumed marker.
        Assert.True(store.Deny(request.AuthReqId));
        Assert.Null(store.Find(request.AuthReqId));
        // Deny of unknown returns false.
        Assert.False(store.Deny("nonexistent"));
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Ciba_store_expired_entry_returns_null_on_find()
    {
        var store = new DistributedCibaPendingRequestStore(CreateCache());
        var request = store.Create("c1", "u1", [], null, TimeSpan.FromMilliseconds(1));

        await Task.Delay(50); // let it expire
        Assert.Null(store.Find(request.AuthReqId));
        await Task.CompletedTask;
    }

    // ---- DPoP nonce store ----

    [Fact]
    public async Task Dpop_nonce_store_issue_current_and_validate()
    {
        var store = new DistributedDpopNonceStore(CreateCache());
        Assert.Null(store.Current());

        var nonce = store.Issue();
        Assert.Equal(nonce, store.Current());
        Assert.True(store.IsValid(nonce));
        Assert.False(store.IsValid("wrong-nonce"));
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Dpop_nonce_store_issue_replaces_previous()
    {
        var store = new DistributedDpopNonceStore(CreateCache());
        var first = store.Issue();
        var second = store.Issue();

        Assert.NotEqual(first, second);
        Assert.True(store.IsValid(second));
        Assert.False(store.IsValid(first));
        await Task.CompletedTask;
    }

    // ---- DPoP replay cache ----

    [Fact]
    public async Task Dpop_replay_cache_first_sighting_is_not_replay()
    {
        var cache = new DistributedDpopReplayCache(CreateCache());
        Assert.False(cache.IsReplay("jti-001", TimeSpan.FromMinutes(5)));
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Dpop_replay_cache_second_sighting_is_replay()
    {
        var cache = new DistributedDpopReplayCache(CreateCache());
        cache.IsReplay("jti-002", TimeSpan.FromMinutes(5));
        Assert.True(cache.IsReplay("jti-002", TimeSpan.FromMinutes(5)));
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Dpop_replay_cache_different_jtis_are_independent()
    {
        var cache = new DistributedDpopReplayCache(CreateCache());
        cache.IsReplay("jti-a", TimeSpan.FromMinutes(5));
        Assert.False(cache.IsReplay("jti-b", TimeSpan.FromMinutes(5)));
        await Task.CompletedTask;
    }
}
