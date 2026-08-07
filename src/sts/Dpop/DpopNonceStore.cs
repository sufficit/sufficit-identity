using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.Tokens;

namespace Sufficit.Identity.STS.Dpop;

/// <summary>
/// Issues and tracks DPoP nonces (RFC 9449 §8) for the AS-side replay-protection
/// dance. When the AS requires nonces, a client's first proof (without a valid
/// <c>nonce</c> claim) is rejected with HTTP 400 <c>use_dpop_nonce</c> and a
/// <c>DPoP-Nonce</c> response header carrying the current nonce; the client
/// retries with that nonce in the proof's <c>nonce</c> claim.
/// </summary>
public interface IDpopNonceStore
{
    /// <summary>
    /// Issues a nonce bound to an endpoint/client/proof-key partition.
    /// </summary>
    string Issue(string partition);

    /// <summary>
    /// Validates the protected nonce, its expiry and exact partition. Nonces
    /// are reusable for concurrent requests during their short lifetime.
    /// </summary>
    bool IsValid(string? nonce, string partition);
}

/// <summary>
/// Stateless DPoP nonce store. Data Protection authenticates the partition,
/// expiry and entropy, so replicas sharing the normal key ring need no global
/// mutable nonce and one client cannot rotate another client's challenge.
/// </summary>
internal sealed class ProtectedDpopNonceStore : IDpopNonceStore
{
    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _ttl;

    public ProtectedDpopNonceStore(
        IDataProtectionProvider dataProtectionProvider,
        TimeSpan? ttl = null,
        TimeProvider? timeProvider = null)
    {
        _protector = dataProtectionProvider.CreateProtector(
            "Sufficit.Identity.DPoP.Nonce.v2");
        _timeProvider = timeProvider ?? TimeProvider.System;
        _ttl = ttl ?? TimeSpan.FromSeconds(60);
    }

    public string Issue(string partition)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(partition);
        var partitionHash = HashPartition(partition);
        var expiresAt = (_timeProvider.GetUtcNow() + _ttl).ToUnixTimeSeconds();
        var entropy = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(24));
        return _protector.Protect($"{partitionHash}|{expiresAt}|{entropy}");
    }

    public bool IsValid(string? nonce, string partition)
    {
        if (string.IsNullOrWhiteSpace(nonce)
            || string.IsNullOrWhiteSpace(partition))
        {
            return false;
        }
        try
        {
            var payload = _protector.Unprotect(nonce);
            var parts = payload.Split('|', 3);
            if (parts.Length != 3
                || !long.TryParse(parts[1], out var expiresAt)
                || expiresAt < _timeProvider.GetUtcNow().ToUnixTimeSeconds())
            {
                return false;
            }

            var expected = Convert.FromHexString(HashPartition(partition));
            var actual = Convert.FromHexString(parts[0]);
            return expected.Length == actual.Length
                && CryptographicOperations.FixedTimeEquals(expected, actual);
        }
        catch (Exception exception) when (exception is CryptographicException or FormatException)
        {
            return false;
        }
    }

    private static string HashPartition(string partition) =>
        Convert.ToHexStringLower(SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(partition)));
}
