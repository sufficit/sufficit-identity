using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Exercises the real database-backed protocol state store.
/// </summary>
/// <remarks>
/// The store is the durable primary for DPoP nonces, front-channel logout
/// context and passkey ceremony tickets (eval 2026-08-30, F-4). Until now every
/// test substituted an in-memory fake, so the parts that only exist in the
/// database implementation — key derivation, expiry comparison, the insert race
/// and removal — had no coverage at all. A store nothing tests is a store
/// nobody can safely change.
/// </remarks>
[Collection(StsCollection.Name)]
public sealed class DatabaseProtocolStateStoreTests
{
    private const string Purpose = "test-purpose";

    private readonly SufficitIdentityTestFactory _factory;

    public DatabaseProtocolStateStoreTests(SufficitIdentityTestFactory factory)
        => _factory = factory;

    private DatabaseProtocolStateStore CreateStore() =>
        new(_factory.Services.GetRequiredService<IDbContextFactory<AppDbContext>>());

    [Fact]
    public async Task Round_trips_a_payload()
    {
        var store = CreateStore();
        var key = "round-trip-" + Guid.NewGuid().ToString("N");

        await store.SetAsync(
            Purpose,
            key,
            Encoding.UTF8.GetBytes("payload"),
            TimeSpan.FromMinutes(5));

        var read = await store.GetAsync(Purpose, key);
        Assert.NotNull(read);
        Assert.Equal("payload", Encoding.UTF8.GetString(read!));
    }

    [Fact]
    public async Task Overwrites_an_existing_key()
    {
        var store = CreateStore();
        var key = "overwrite-" + Guid.NewGuid().ToString("N");

        await store.SetAsync(Purpose, key, Encoding.UTF8.GetBytes("first"), TimeSpan.FromMinutes(5));
        await store.SetAsync(Purpose, key, Encoding.UTF8.GetBytes("second"), TimeSpan.FromMinutes(5));

        Assert.Equal(
            "second",
            Encoding.UTF8.GetString((await store.GetAsync(Purpose, key))!));
    }

    [Fact]
    public async Task Expired_entry_reads_as_absent()
    {
        var store = CreateStore();
        var key = "expired-" + Guid.NewGuid().ToString("N");

        // A lifetime already in the past: the row exists but must not be served.
        await store.SetAsync(
            Purpose,
            key,
            Encoding.UTF8.GetBytes("stale"),
            TimeSpan.FromSeconds(-1));

        Assert.Null(await store.GetAsync(Purpose, key));
    }

    [Fact]
    public async Task Removal_is_effective()
    {
        var store = CreateStore();
        var key = "removed-" + Guid.NewGuid().ToString("N");

        await store.SetAsync(Purpose, key, Encoding.UTF8.GetBytes("x"), TimeSpan.FromMinutes(5));
        await store.RemoveAsync(Purpose, key);

        Assert.Null(await store.GetAsync(Purpose, key));
    }

    [Fact]
    public async Task Purposes_are_separate_namespaces()
    {
        var store = CreateStore();
        var key = "shared-key-" + Guid.NewGuid().ToString("N");

        await store.SetAsync("purpose-a", key, Encoding.UTF8.GetBytes("a"), TimeSpan.FromMinutes(5));
        await store.SetAsync("purpose-b", key, Encoding.UTF8.GetBytes("b"), TimeSpan.FromMinutes(5));

        Assert.Equal("a", Encoding.UTF8.GetString((await store.GetAsync("purpose-a", key))!));
        Assert.Equal("b", Encoding.UTF8.GetString((await store.GetAsync("purpose-b", key))!));
    }

    [Fact]
    public async Task Concurrent_writes_to_the_same_key_do_not_throw()
    {
        // The insert race: Find-then-Add is not atomic, so parallel writers for
        // one partition both see no row and both insert. This used to surface
        // as a 500 on the token endpoint (one client issuing parallel token
        // requests is the ordinary trigger for the DPoP nonce dance).
        var store = CreateStore();
        var key = "race-" + Guid.NewGuid().ToString("N");

        var writers = Enumerable.Range(0, 8).Select(i => Task.Run(() =>
            store.SetAsync(
                Purpose,
                key,
                Encoding.UTF8.GetBytes("writer-" + i),
                TimeSpan.FromMinutes(5))));

        var failure = await Record.ExceptionAsync(() => Task.WhenAll(writers));

        Assert.Null(failure);
        Assert.NotNull(await store.GetAsync(Purpose, key));
    }

    [Fact]
    public void Synchronous_surface_round_trips()
    {
        // The DPoP nonce store is synchronous by interface, so this path is
        // just as load-bearing as the async one.
        var store = CreateStore();
        var key = "sync-" + Guid.NewGuid().ToString("N");

        store.Set(Purpose, key, Encoding.UTF8.GetBytes("sync"), TimeSpan.FromMinutes(5));
        Assert.Equal("sync", Encoding.UTF8.GetString(store.Get(Purpose, key)!));

        store.Remove(Purpose, key);
        Assert.Null(store.Get(Purpose, key));
    }
}
