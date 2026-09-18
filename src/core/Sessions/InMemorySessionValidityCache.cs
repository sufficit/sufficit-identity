using System.Collections.Concurrent;

namespace Sufficit.Identity.Core.Sessions;

/// <summary>
/// Process-local <see cref="ISessionValidityCache"/>. Entries are bounded in
/// number and in age, so a busy server cannot grow the table without limit and
/// a lost invalidation notice cannot keep a revoked session alive longer than
/// the window.
/// </summary>
public sealed class InMemorySessionValidityCache : ISessionValidityCache
{
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _window;
    private readonly int _capacity;

    public InMemorySessionValidityCache(
        TimeSpan window,
        TimeProvider? timeProvider = null,
        int capacity = 50_000)
    {
        _window = window;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _capacity = Math.Max(1, capacity);
    }

    public bool IsRevalidationNeeded(string userId, DateTimeOffset verifiedAt)
    {
        ArgumentException.ThrowIfNullOrEmpty(userId);

        if (_window <= TimeSpan.Zero)
        {
            return true;
        }

        var now = _timeProvider.GetUtcNow();
        if (now - verifiedAt >= _window)
        {
            return true;
        }

        if (!_entries.TryGetValue(userId, out var entry))
        {
            // Nothing known about this user on this node: read the row.
            return true;
        }

        // A ticket verified before the last invalidation says nothing about the
        // user's current state, and an entry older than the window is not
        // trusted either.
        return verifiedAt <= entry.InvalidatedAt || now - entry.VerifiedAt >= _window;
    }

    public void MarkVerified(string userId)
    {
        ArgumentException.ThrowIfNullOrEmpty(userId);

        if (_window <= TimeSpan.Zero)
        {
            return;
        }

        var now = _timeProvider.GetUtcNow();
        Prune(now);
        _entries.AddOrUpdate(
            userId,
            _ => new Entry(now, DateTimeOffset.MinValue),
            (_, existing) => existing with { VerifiedAt = now });
    }

    public void Invalidate(string userId)
    {
        ArgumentException.ThrowIfNullOrEmpty(userId);

        var now = _timeProvider.GetUtcNow();
        _entries.AddOrUpdate(
            userId,
            _ => new Entry(DateTimeOffset.MinValue, now),
            (_, existing) => existing with { InvalidatedAt = now });
    }

    /// <summary>
    /// Drops what the window has already expired, and everything when the
    /// table is full: an entry that is gone only costs one extra read.
    /// </summary>
    private void Prune(DateTimeOffset now)
    {
        if (_entries.Count < _capacity)
        {
            return;
        }

        foreach (var (key, entry) in _entries)
        {
            if (now - entry.VerifiedAt >= _window && now - entry.InvalidatedAt >= _window)
            {
                _entries.TryRemove(key, out _);
            }
        }

        if (_entries.Count >= _capacity)
        {
            _entries.Clear();
        }
    }

    private readonly record struct Entry(
        DateTimeOffset VerifiedAt,
        DateTimeOffset InvalidatedAt);
}
