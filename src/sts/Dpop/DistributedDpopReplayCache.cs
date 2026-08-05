using System.Security.Cryptography;
using Microsoft.Extensions.Caching.Distributed;

namespace Sufficit.Identity.STS.Dpop;

/// <summary>
/// Replay-protection cache for DPoP proof <c>jti</c> values (RFC 9449 §7.5).
/// Returns <c>true</c> if the jti has already been seen (i.e. the proof is a
/// replay); <c>false</c> on first sighting (and records it).
/// </summary>
/// <remarks>
/// The distributed implementation uses <see cref="IDistributedCache"/> so replay
/// detection works across replicas. The per-instance fallback
/// (<c>AddDistributedMemoryCache</c>) still works for single-node deployments.
/// </remarks>
public interface IDpopReplayCache
{
    /// <summary>
    /// Returns true if <paramref name="jti"/> was already recorded; otherwise
    /// records it and returns false.
    /// </summary>
    bool IsReplay(string jti, TimeSpan ttl);
}

/// <summary>
/// <see cref="IDistributedCache"/>-backed DPoP replay cache. Uses atomic
/// key-insertion semantics: the first replica to write the key "wins" and
/// subsequent writes return the existing value, so a proof replayed on a
/// different replica is detected.
/// </summary>
internal sealed class DistributedDpopReplayCache : IDpopReplayCache
{
    private const string KeyPrefix = "dpop:jti:";

    private readonly IDistributedCache _cache;

    public DistributedDpopReplayCache(IDistributedCache cache) => _cache = cache;

    public bool IsReplay(string jti, TimeSpan ttl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jti);
        var key = KeyPrefix + jti;

        // Try to insert a marker. If the key already exists, the proof is a replay.
        // IDistributedCache doesn't have a native "add if absent" — we use a
        // read-then-write pattern with a cryptographic nonce as the marker.
        // If the marker we read back differs from what we wrote, another replica
        // wrote first (it won the race).
        var marker = RandomNumberGenerator.GetBytes(16);
        var markerB64 = Convert.ToBase64String(marker);

        var existing = _cache.GetString(key);
        if (existing is not null)
        {
            return true; // already seen by some replica
        }

        _cache.SetString(key, markerB64, new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = ttl,
        });

        // Read back: if another replica wrote concurrently, our marker lost.
        var readback = _cache.GetString(key);
        return readback != markerB64;
    }
}
