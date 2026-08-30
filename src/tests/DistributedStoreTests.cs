using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Ciba;
using Sufficit.Identity.STS.Dpop;
using Sufficit.Identity.Vault;
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
    public void Ciba_store_encrypts_pending_json_when_vault_is_enabled()
    {
        var cache = CreateCache();
        var store = new DistributedCibaPendingRequestStore(
            cache,
            keyVault: new PassThroughKeyVault());

        var request = store.Create("test-client", "user-1", ["openid"], null,
            TimeSpan.FromMinutes(5));

        var raw = cache.GetString("ciba:pending:" + request.AuthReqId);
        Assert.NotNull(raw);
        Assert.StartsWith("pt1.", raw, StringComparison.Ordinal);
        Assert.DoesNotContain("test-client", raw, StringComparison.Ordinal);
        Assert.Equal("test-client", store.Find(request.AuthReqId)!.ClientId);
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
    public async Task Dpop_nonce_is_valid_only_for_its_exact_partition()
    {
        var store = new ProtectedDpopNonceStore(
            new EphemeralDataProtectionProvider());

        var nonce = store.Issue("/connect/token|client-a|key-a");
        Assert.True(store.IsValid(nonce, "/connect/token|client-a|key-a"));
        Assert.False(store.IsValid(nonce, "/connect/token|client-b|key-a"));
        Assert.False(store.IsValid(nonce, "/connect/token|client-a|key-b"));
        Assert.False(store.IsValid("wrong-nonce", "/connect/token|client-a|key-a"));
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Dpop_nonce_issuance_does_not_invalidate_concurrent_challenges()
    {
        var store = new ProtectedDpopNonceStore(
            new EphemeralDataProtectionProvider());
        const string partition = "/connect/token|client-a|key-a";
        var first = store.Issue(partition);
        var second = store.Issue(partition);

        Assert.NotEqual(first, second);
        Assert.True(store.IsValid(first, partition));
        Assert.True(store.IsValid(second, partition));
        await Task.CompletedTask;
    }

    [Fact]
    public void Distributed_dpop_nonce_encrypts_cache_payload_when_vault_is_enabled()
    {
        var cache = CreateCache();
        var store = new DistributedDpopNonceStore(
            cache,
            keyVault: new PassThroughKeyVault());
        const string partition = "/connect/token|client-a|key-a";

        var nonce = store.Issue(partition);
        Assert.True(store.IsValid(nonce, partition));

        var cacheKey = "dpop:nonce:v2:" + Convert.ToHexStringLower(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(partition)));
        var raw = cache.GetString(cacheKey);
        Assert.NotNull(raw);
        Assert.StartsWith("pt1.", raw, StringComparison.Ordinal);
        Assert.DoesNotContain(nonce, raw, StringComparison.Ordinal);
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

    // ---- Durable-primary DPoP nonce store (eval 2026-08-30, F-4) ----

    [Fact]
    public void Rolling_nonce_store_issues_from_the_durable_primary()
    {
        // The whole point of the durable primary: the challenge must be
        // resolvable by a replica that never saw the issuing request, which the
        // process-local cache could not do.
        var state = new InMemoryProtocolStateStore();
        var database = new DatabaseDpopNonceStore(state);
        var rolling = new RollingDpopNonceStore(
            database,
            new DistributedDpopNonceStore(CreateCache()));

        var nonce = rolling.Issue("partition-a");

        Assert.True(database.IsValid(nonce, "partition-a"));
        // A different replica reading the same durable store agrees.
        Assert.True(
            new DatabaseDpopNonceStore(state).IsValid(nonce, "partition-a"));
    }

    [Fact]
    public void Rolling_nonce_store_still_accepts_a_legacy_cache_nonce()
    {
        // During a rolling deployment a not-yet-upgraded replica issues into
        // the cache only; that challenge must keep working for its lifetime.
        var cache = CreateCache();
        var legacy = new DistributedDpopNonceStore(cache);
        var rolling = new RollingDpopNonceStore(
            new DatabaseDpopNonceStore(new InMemoryProtocolStateStore()),
            legacy);

        var legacyNonce = legacy.Issue("partition-b");

        Assert.True(rolling.IsValid(legacyNonce, "partition-b"));
    }

    [Fact]
    public void Nonce_is_bound_to_its_partition()
    {
        var rolling = new RollingDpopNonceStore(
            new DatabaseDpopNonceStore(new InMemoryProtocolStateStore()),
            new DistributedDpopNonceStore(CreateCache()));

        var nonce = rolling.Issue("partition-c");

        Assert.False(rolling.IsValid(nonce, "partition-d"));
        Assert.False(rolling.IsValid("not-the-nonce", "partition-c"));
    }

    /// <summary>
    /// Minimal in-process <see cref="IProtocolStateStore"/> so the store
    /// semantics can be asserted without a database. The production
    /// registration is <c>DatabaseProtocolStateStore</c>.
    /// </summary>
    private sealed class InMemoryProtocolStateStore : IProtocolStateStore
    {
        private readonly Dictionary<string, (byte[] Payload, DateTimeOffset ExpiresAt)> _entries
            = new(StringComparer.Ordinal);

        public byte[]? Get(string purpose, string key) =>
            _entries.TryGetValue(purpose + "" + key, out var entry)
                && entry.ExpiresAt > DateTimeOffset.UtcNow
                    ? entry.Payload
                    : null;

        public void Set(string purpose, string key, byte[] payload, TimeSpan lifetime) =>
            _entries[purpose + "" + key] =
                (payload, DateTimeOffset.UtcNow + lifetime);

        public void Remove(string purpose, string key) =>
            _entries.Remove(purpose + "" + key);

        public Task<byte[]?> GetAsync(
            string purpose,
            string key,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(Get(purpose, key));

        public Task SetAsync(
            string purpose,
            string key,
            byte[] payload,
            TimeSpan lifetime,
            CancellationToken cancellationToken = default)
        {
            Set(purpose, key, payload, lifetime);
            return Task.CompletedTask;
        }

        public Task RemoveAsync(
            string purpose,
            string key,
            CancellationToken cancellationToken = default)
        {
            Remove(purpose, key);
            return Task.CompletedTask;
        }
    }
}
