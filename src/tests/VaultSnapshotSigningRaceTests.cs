using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.Vault;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// A signing-key load that started before an invalidation must not be cached
/// after it: the pre-rotation list would hide the new version until the entry
/// expired (JWKS without the key that signs new tokens).
/// </summary>
public sealed class VaultSnapshotSigningRaceTests
{
    private static VaultSigningKey Key(int version) =>
        new("oidc-signing", version, $"vault:oidc-signing:{version}", "{}");

    private static VaultSnapshotCache Cache() =>
        new(null!, new VaultSnapshotOptions(), NullLogger<VaultSnapshotCache>.Instance);

    [Fact]
    public async Task A_load_overtaken_by_an_invalidation_is_returned_but_not_cached()
    {
        var cache = Cache();

        // The rotation commits and invalidates (in another flow) while this
        // load is in flight.
        var rotated = new TaskCompletionSource();
        var stale = await cache.GetSigningKeysAsync("oidc-signing", async ct =>
        {
            // Another request's flow: nothing of this load's context flows in.
            Task rotation;
            using (ExecutionContext.SuppressFlow())
            {
                rotation = Task.Run(async () =>
                {
                    await cache.InvalidateSigningKeysAsync("oidc-signing", CancellationToken.None);
                    rotated.SetResult();
                });
            }
            await rotation;
            await rotated.Task;
            return [Key(1)];
        }, CancellationToken.None);
        Assert.Single(stale);

        var next = await cache.GetSigningKeysAsync("oidc-signing",
            _ => Task.FromResult<IReadOnlyList<VaultSigningKey>>([Key(1), Key(2)]),
            CancellationToken.None);
        Assert.Contains(next, key => key.KeyVersion == 2);
    }

    [Fact]
    public async Task A_remote_invalidation_during_a_load_also_prevents_caching()
    {
        var cache = Cache();

        await cache.GetSigningKeysAsync("oidc-signing", ct =>
        {
            cache.ApplyRemoteInvalidation(new VaultSnapshotInvalidation("signing", "other-replica", null));
            return Task.FromResult<IReadOnlyList<VaultSigningKey>>([Key(1)]);
        }, CancellationToken.None);

        var next = await cache.GetSigningKeysAsync("oidc-signing",
            _ => Task.FromResult<IReadOnlyList<VaultSigningKey>>([Key(1), Key(2)]),
            CancellationToken.None);
        Assert.Equal(2, next.Count);
    }

    [Fact]
    public async Task An_empty_key_list_is_never_cached()
    {
        var cache = Cache();

        Assert.Empty(await cache.GetSigningKeysAsync("oidc-signing",
            _ => Task.FromResult<IReadOnlyList<VaultSigningKey>>([]), CancellationToken.None));

        var next = await cache.GetSigningKeysAsync("oidc-signing",
            _ => Task.FromResult<IReadOnlyList<VaultSigningKey>>([Key(1)]), CancellationToken.None);
        Assert.Single(next);
    }

    [Fact]
    public async Task A_load_that_invalidates_itself_is_still_cached()
    {
        // First use: the loader creates v1 and invalidates; its own result
        // already includes that version.
        var cache = Cache();
        await cache.GetSigningKeysAsync("oidc-signing", async ct =>
        {
            await cache.InvalidateSigningKeysAsync("oidc-signing", ct);
            return [Key(1)];
        }, CancellationToken.None);

        var cached = await cache.GetSigningKeysAsync("oidc-signing",
            _ => throw new InvalidOperationException("must come from the cache"), CancellationToken.None);
        Assert.Single(cached);
    }

    [Fact]
    public async Task An_undisturbed_load_is_still_cached()
    {
        var cache = Cache();
        await cache.GetSigningKeysAsync("oidc-signing",
            _ => Task.FromResult<IReadOnlyList<VaultSigningKey>>([Key(1)]), CancellationToken.None);

        var cached = await cache.GetSigningKeysAsync("oidc-signing",
            _ => throw new InvalidOperationException("must come from the cache"), CancellationToken.None);
        Assert.Single(cached);
    }
}
