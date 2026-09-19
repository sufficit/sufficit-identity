using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Sufficit.Identity.STS;

/// <summary>
/// What this deployment knows about breached passwords without asking anyone:
/// the range answers it has already been given, and a list of passwords it
/// refuses on its own.
/// </summary>
/// <remarks>
/// Shared by every validation, so it is registered as a singleton while the
/// validator itself stays scoped.
///
/// The cache is the more useful half. A range answer covers every password
/// sharing its five-character prefix, so a deployment that has been running
/// answers most repeat prefixes from memory, and an outage stops mattering for
/// those — which is the common case for the passwords people actually pick.
/// </remarks>
public sealed class BreachedPasswordKnowledge
{
    /// <summary>
    /// A floor, not a list of every breached password — that is what the
    /// remote service is for. These are the ones that appear at the top of
    /// every breach corpus, so refusing them locally means the fallback is
    /// never worse than useless.
    /// </summary>
    private static readonly string[] BuiltInFloor =
    [
        "123456", "123456789", "12345678", "password", "qwerty", "111111",
        "12345", "123123", "1234567", "1234567890", "000000", "abc123",
        "iloveyou", "qwerty123", "1q2w3e4r", "admin", "qwertyuiop", "654321",
        "555555", "lovely", "7777777", "888888", "princess", "dragon",
        "password1", "123qwe", "letmein", "monkey", "sunshine", "master",
        "welcome", "shadow", "ashley", "football", "jesus", "michael",
        "ninja", "mustang", "senha", "senha123", "123mudar", "mudar123",
        "brasil", "flamengo", "corinthians", "gremio", "palmeiras",
    ];

    private readonly ConcurrentDictionary<string, CacheEntry> _ranges = new(
        StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _local;
    private readonly int _cacheSize;
    private readonly TimeSpan _cacheLifetime;
    private readonly TimeProvider _timeProvider;

    public BreachedPasswordKnowledge(
        PasswordPolicyOptions options,
        ILogger<BreachedPasswordKnowledge>? logger = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _timeProvider = timeProvider ?? TimeProvider.System;
        _cacheSize = Math.Clamp(options.BreachedRangeCacheSize, 1, 100_000);
        _cacheLifetime = TimeSpan.FromMinutes(
            Math.Clamp(options.BreachedRangeCacheMinutes, 1, 24 * 60));
        _local = new HashSet<string>(BuiltInFloor, StringComparer.Ordinal);

        var path = options.LocalBreachedPasswordListPath;
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        try
        {
            var added = 0;
            foreach (var line in File.ReadLines(path))
            {
                var value = line.Trim();
                if (value.Length == 0 || value.StartsWith('#'))
                {
                    continue;
                }

                if (_local.Add(value))
                {
                    added++;
                }
            }

            logger?.LogInformation(
                "Local breached-password list loaded: {Added} entries from {Path}.",
                added,
                path);
        }
        catch (Exception exception)
            when (exception is IOException or UnauthorizedAccessException)
        {
            // A missing or unreadable list leaves the built-in floor. Refusing
            // to start over it would trade a weaker fallback for no service.
            logger?.LogWarning(
                exception,
                "Local breached-password list could not be read from {Path}; "
                + "the built-in floor is still in effect.",
                path);
        }
    }

    /// <summary>Entries the local list refuses, for diagnostics.</summary>
    public int LocalEntryCount => _local.Count;

    public bool IsLocallyKnownBreached(string password) =>
        _local.Contains(password);

    /// <summary>
    /// The suffixes of a cached range, or <see langword="null"/> when this
    /// prefix has not been answered recently.
    /// </summary>
    public IReadOnlySet<string>? TryGetRange(string prefix)
    {
        if (!_ranges.TryGetValue(prefix, out var entry))
        {
            return null;
        }

        if (entry.ExpiresAt <= _timeProvider.GetUtcNow())
        {
            _ranges.TryRemove(prefix, out _);
            return null;
        }

        return entry.Suffixes;
    }

    public void StoreRange(string prefix, IReadOnlySet<string> suffixes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(prefix);
        ArgumentNullException.ThrowIfNull(suffixes);

        // Bounded by dropping the oldest, so a long-running host cannot grow
        // this without limit. Exact LRU would need a lock on every read; the
        // cost of evicting a still-useful entry is one more request.
        while (_ranges.Count >= _cacheSize)
        {
            var oldest = _ranges
                .OrderBy(entry => entry.Value.ExpiresAt)
                .Select(entry => entry.Key)
                .FirstOrDefault();
            if (oldest is null || !_ranges.TryRemove(oldest, out _))
            {
                break;
            }
        }

        _ranges[prefix] = new CacheEntry(
            suffixes,
            _timeProvider.GetUtcNow() + _cacheLifetime);
    }

    private sealed record CacheEntry(
        IReadOnlySet<string> Suffixes,
        DateTimeOffset ExpiresAt);
}
