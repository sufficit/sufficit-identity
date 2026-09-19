using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.STS.Dpop;

/// <summary>
/// DPoP nonce store (RFC 9449 §8) with a durable primary, so a nonce issued by
/// one replica is honored by every other one and survives a restart.
/// </summary>
/// <remarks>
/// The previous implementation kept nonces only in <c>IDistributedCache</c>,
/// which defaults to process-local memory: with more than one replica the
/// client's retry landed on a host that had never heard of the challenge and
/// the nonce dance never converged (eval 2026-08-30, F-4). The payload stays
/// encrypted through <see cref="IKeyVault"/>, so nonce material is not exposed
/// at rest in the shared table.
/// </remarks>
internal sealed class DatabaseDpopNonceStore : IDpopNonceStore
{
    internal const string StatePurpose = "dpop-nonce";

    private readonly IProtocolStateStore _state;
    private readonly IKeyVault? _keyVault;
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _ttl;

    public DatabaseDpopNonceStore(
        IProtocolStateStore state,
        TimeSpan? ttl = null,
        TimeProvider? timeProvider = null,
        IKeyVault? keyVault = null)
    {
        _state = state;
        _ttl = ttl ?? TimeSpan.FromSeconds(60);
        _timeProvider = timeProvider ?? TimeProvider.System;
        _keyVault = keyVault;
    }

    public string Issue(string partition)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(partition);

        var nonce = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(24));
        var expiresAt = _timeProvider.GetUtcNow() + _ttl;
        // Same "nonce|expiry" framing as the cache store, so the value can be
        // validated without a second lookup.
        var payload = DpopNonceProtection.Encrypt(
            _keyVault,
            $"{nonce}|{expiresAt:O}",
            partition);

        _state.Set(StatePurpose, partition, Encoding.UTF8.GetBytes(payload), _ttl);
        return nonce;
    }

    public bool IsValid(string? nonce, string partition)
    {
        if (string.IsNullOrEmpty(nonce) || string.IsNullOrWhiteSpace(partition))
        {
            return false;
        }

        return string.Equals(nonce, Current(partition), StringComparison.Ordinal);
    }

    private string? Current(string partition)
    {
        var stored = _state.Get(StatePurpose, partition);
        if (stored is null || stored.Length == 0)
        {
            return null;
        }

        var parts = DpopNonceProtection
            .Decrypt(_keyVault, Encoding.UTF8.GetString(stored), partition)
            .Split('|');
        if (parts.Length != 2)
        {
            return null;
        }

        // The row's own expiry already bounds this, but the embedded timestamp
        // is what the cache store checks too — keep both honest.
        return DateTimeOffset.TryParse(parts[1], out var expiresAt)
            && expiresAt >= _timeProvider.GetUtcNow()
                ? parts[0]
                : null;
    }
}

/// <summary>
/// Issues stateless nonces and still accepts the ones the two earlier stores
/// issued, for as long as a rolling deployment can produce them.
/// </summary>
/// <remarks>
/// The durable store keeps <em>one</em> value per partition, so issuing a
/// challenge overwrote the previous one: a client with two token requests in
/// flight had its first retry fail because of its second request. The handler
/// that issues challenges was written for a stateless store and says so in its
/// comments; the registration had drifted to this one (eval 2026-08-30, F-4,
/// which fixed multi-replica convergence and did not notice the overwrite).
///
/// <see cref="ProtectedDpopNonceStore"/> keeps nothing. The nonce is its own
/// proof — partition, expiry and entropy authenticated by Data Protection — so
/// every nonce stays valid for its lifetime, concurrent challenges cannot
/// displace each other, and there is no shared value for anyone to rotate. It
/// converges across replicas through the key ring, which the host persists to
/// the database and which the authentication cookies already depend on.
///
/// The durable and cache stores are validation-only here: a replica still on
/// the previous release issues through them, and those challenges have to keep
/// working for their sixty seconds. Remove both one release after this one.
/// </remarks>
internal sealed class RollingDpopNonceStore(
    ProtectedDpopNonceStore issuer,
    DatabaseDpopNonceStore database,
    DistributedDpopNonceStore legacy) : IDpopNonceStore
{
    public string Issue(string partition) => issuer.Issue(partition);

    public bool IsValid(string? nonce, string partition) =>
        issuer.IsValid(nonce, partition)
        || database.IsValid(nonce, partition)
        || legacy.IsValid(nonce, partition);
}

/// <summary>
/// Shared confidentiality helpers for the nonce payload. Extracted so the cache
/// and database stores cannot drift into two different encodings of the same
/// security-relevant value.
/// </summary>
internal static class DpopNonceProtection
{
    private const string VaultKeyName = "dpop-nonce";

    public static string Encrypt(IKeyVault? keyVault, string payload, string partition)
    {
        if (keyVault is null)
        {
            return payload;
        }

        return keyVault.EncryptAsync(VaultKeyName, payload, CreateAad(partition))
            .GetAwaiter()
            .GetResult();
    }

    public static string Decrypt(IKeyVault? keyVault, string value, string partition)
    {
        // A null vault is used by the focused unit tests and preserves the
        // original plaintext contract. Existing plaintext values are accepted
        // during a rolling deployment and replaced on the next Issue call.
        if (keyVault is null || !LooksLikeVaultValue(value))
        {
            return value;
        }

        try
        {
            return keyVault.DecryptStringAsync(value, CreateAad(partition))
                .GetAwaiter()
                .GetResult();
        }
        catch (FormatException)
        {
            return value;
        }
        catch (CryptographicException)
        {
            return string.Empty;
        }
    }

    public static IReadOnlyDictionary<string, string> CreateAad(string partition) =>
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["scope"] = VaultKeyName,
            ["partition"] = Convert.ToHexStringLower(
                SHA256.HashData(Encoding.UTF8.GetBytes(partition))),
        };

    private static bool LooksLikeVaultValue(string value) =>
        value.StartsWith("v1.", StringComparison.Ordinal)
        || value.StartsWith("pt1.", StringComparison.Ordinal);
}
