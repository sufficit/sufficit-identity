using Sufficit.Identity.Core.Sessions;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// The security stamp is read on every cookie-authenticated request. This
/// cache is what lets a request skip that read, so its rules are the whole
/// safety argument: never skip without a prior verification, never skip past
/// an invalidation, and never skip beyond the window that bounds a lost
/// notification (A9, closes V7).
/// </summary>
public sealed class SessionValidityCacheTests
{
    private const string User = "user-1";

    [Fact]
    public void An_unknown_user_is_always_read_from_the_store()
    {
        var (cache, time) = Create(TimeSpan.FromSeconds(30));

        Assert.True(cache.IsRevalidationNeeded(User, time.GetUtcNow()));
    }

    [Fact]
    public void A_verified_user_is_trusted_inside_the_window()
    {
        var (cache, time) = Create(TimeSpan.FromSeconds(30));
        cache.MarkVerified(User);
        var verifiedAt = time.GetUtcNow();

        time.Advance(TimeSpan.FromSeconds(10));

        Assert.False(cache.IsRevalidationNeeded(User, verifiedAt));
    }

    [Fact]
    public void The_window_expires_the_trust()
    {
        var (cache, time) = Create(TimeSpan.FromSeconds(30));
        cache.MarkVerified(User);
        var verifiedAt = time.GetUtcNow();

        time.Advance(TimeSpan.FromSeconds(31));

        Assert.True(cache.IsRevalidationNeeded(User, verifiedAt));
    }

    [Fact]
    public void An_invalidation_after_the_verification_forces_a_read()
    {
        var (cache, time) = Create(TimeSpan.FromSeconds(30));
        cache.MarkVerified(User);
        var verifiedAt = time.GetUtcNow();

        time.Advance(TimeSpan.FromSeconds(1));
        cache.Invalidate(User);

        Assert.True(cache.IsRevalidationNeeded(User, verifiedAt));
    }

    [Fact]
    public void An_invalidation_of_another_user_changes_nothing()
    {
        var (cache, time) = Create(TimeSpan.FromSeconds(30));
        cache.MarkVerified(User);
        var verifiedAt = time.GetUtcNow();

        time.Advance(TimeSpan.FromSeconds(1));
        cache.Invalidate("user-2");

        Assert.False(cache.IsRevalidationNeeded(User, verifiedAt));
    }

    [Fact]
    public void A_zero_window_disables_the_cache_entirely()
    {
        var (cache, time) = Create(TimeSpan.Zero);
        cache.MarkVerified(User);

        Assert.True(cache.IsRevalidationNeeded(User, time.GetUtcNow()));
    }

    [Fact]
    public void A_full_table_does_not_grow_without_bound()
    {
        var (cache, time) = Create(TimeSpan.FromSeconds(30), capacity: 8);

        for (var index = 0; index < 100; index++)
        {
            cache.MarkVerified($"user-{index}");
        }

        // Whatever survived pruning, a dropped entry only costs one more read.
        var verifiedAt = time.GetUtcNow();
        var reads = Enumerable
            .Range(0, 100)
            .Count(index => cache.IsRevalidationNeeded($"user-{index}", verifiedAt));
        Assert.True(reads > 0);
    }

    private static (ISessionValidityCache Cache, MutableTimeProvider Time) Create(
        TimeSpan window,
        int capacity = 50_000)
    {
        var time = new MutableTimeProvider(DateTimeOffset.UtcNow);
        return (new InMemorySessionValidityCache(window, time, capacity), time);
    }

    private sealed class MutableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan duration) => _utcNow += duration;
    }
}
