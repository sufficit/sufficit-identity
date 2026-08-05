using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Sufficit.Identity.STS.Dpop;

/// <summary>
/// Issues and tracks DPoP nonces (RFC 9449 §8) for the AS-side replay-protection
/// dance. When the AS requires nonces, a client's first proof (without a valid
/// <c>nonce</c> claim) is rejected with HTTP 400 <c>use_dpop_nonce</c> and a
/// <c>DPoP-Nonce</c> response header carrying the current nonce; the client
/// retries with that nonce in the proof's <c>nonce</c> claim.
/// </summary>
/// <remarks>
/// <b>Scope.</b> Single-instance STS. For multi-replica, swap for a shared
/// cache (Redis); the interface isolates that change. A nonce is per-AS (one
/// current value at a time, rotated on issue) — RFC 9449 §8 allows either a
/// per-AS or per-client nonce; per-AS is simpler and standard. The TTL is
/// short (default 60s) so a leaked nonce is short-lived.
/// </remarks>
public interface IDpopNonceStore
{
    /// <summary>
    /// Returns the current valid nonce for this AS, or null if none is in
    /// force (the caller then decides whether to challenge).
    /// </summary>
    string? Current();

    /// <summary>
    /// Issues a fresh nonce (invalidating any previous one) and returns it.
    /// Use when the AS decides to start/re-arm the nonce challenge.
    /// </summary>
    string Issue();

    /// <summary>
    /// Validates that <paramref name="nonce"/> matches the current nonce and is
    /// not expired. Does NOT consume the nonce (a nonce is reusable within its
    /// TTL — multiple concurrent requests may carry the same valid nonce).
    /// </summary>
    bool IsValid(string? nonce);
}

internal sealed class InMemoryDpopNonceStore : IDpopNonceStore
{
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _ttl;
    private (string Nonce, DateTimeOffset ExpiresAt) _current;

    public InMemoryDpopNonceStore(TimeSpan? ttl = null, TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _ttl = ttl ?? TimeSpan.FromSeconds(60);
    }

    public string? Current()
    {
        var (nonce, expiresAt) = _current;
        if (nonce is null || expiresAt < _timeProvider.GetUtcNow())
        {
            return null;
        }
        return nonce;
    }

    public string Issue()
    {
        // 192 bits of entropy, base64url-encoded. RFC 9449 §8 does not mandate
        // a length; this is comfortably unguessable.
        var bytes = RandomNumberGenerator.GetBytes(24);
        var nonce = Base64UrlEncoder.Encode(bytes);
        _current = (nonce, _timeProvider.GetUtcNow() + _ttl);
        return nonce;
    }

    public bool IsValid(string? nonce)
    {
        if (string.IsNullOrEmpty(nonce)) return false;
        var (current, expiresAt) = _current;
        if (current is null || expiresAt < _timeProvider.GetUtcNow()) return false;
        return string.Equals(current, nonce, StringComparison.Ordinal);
    }
}
