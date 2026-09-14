using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Core.Services;

/// <summary>
/// Issues, finds and consumes initial access tokens for dynamic client
/// registration. The management API issues and revokes; the registration
/// endpoint finds and consumes.
/// </summary>
public sealed class DcrInitialAccessTokenStore(
    IDbContextFactory<AppDbContext> databaseFactory,
    TimeProvider? timeProvider = null)
{
    /// <summary>Marks the value as a registration credential in logs and scanners.</summary>
    public const string TokenPrefix = "dcr_iat_";

    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Creates a token and its record. The plaintext token is returned once
    /// and never stored.
    /// </summary>
    public static (DcrInitialAccessToken Record, string Token) Create(
        string label,
        string issuedBy,
        DateTime createdAtUtc,
        TimeSpan lifetime,
        bool singleUse)
    {
        var token = TokenPrefix + Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        var hash = Hash(token);
        return (new DcrInitialAccessToken
        {
            Id = Guid.NewGuid(),
            Label = label,
            TokenHash = hash,
            TokenHint = hash[..IdentityDatabaseSchema.DcrInitialAccessTokenHintLength],
            IssuedBy = issuedBy,
            CreatedAtUtc = createdAtUtc,
            ExpiresAtUtc = createdAtUtc + lifetime,
            SingleUse = singleUse,
        }, token);
    }

    public static string Hash(string token) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    public static bool IsActive(DcrInitialAccessToken token, DateTime nowUtc) =>
        token.RevokedAtUtc is null
        && token.ExpiresAtUtc > nowUtc
        && (!token.SingleUse || token.RegistrationCount == 0);

    /// <summary>Returns the token record when the presented value is usable now.</summary>
    public async Task<DcrInitialAccessToken?> FindActiveAsync(
        string? token,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return null;
        }

        var hash = Hash(token);
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        var record = await database.DcrInitialAccessTokens
            .AsNoTracking()
            .SingleOrDefaultAsync(x => x.TokenHash == hash, cancellationToken);
        return record is not null && IsActive(record, _timeProvider.GetUtcNow().UtcDateTime)
            ? record
            : null;
    }

    /// <summary>
    /// Records one registration against the token. The conditional update is
    /// atomic, so of two concurrent registrations presenting the same
    /// single-use token exactly one succeeds.
    /// </summary>
    public async Task<bool> TryConsumeAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        var now = _timeProvider.GetUtcNow().UtcDateTime;
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        var affected = await database.DcrInitialAccessTokens
            .Where(x => x.Id == id
                && x.RevokedAtUtc == null
                && x.ExpiresAtUtc > now
                && (!x.SingleUse || x.RegistrationCount == 0))
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(x => x.RegistrationCount, x => x.RegistrationCount + 1)
                .SetProperty(x => x.LastUsedAtUtc, now),
                cancellationToken);
        return affected == 1;
    }
}
