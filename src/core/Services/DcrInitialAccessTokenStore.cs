using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
        bool singleUse,
        IReadOnlyCollection<string>? allowedGrantTypes = null,
        IReadOnlyCollection<string>? allowedScopes = null)
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
            AllowedGrantTypesJson = WriteList(allowedGrantTypes),
            AllowedScopesJson = WriteList(allowedScopes),
        }, token);
    }

    /// <summary>
    /// Reads a stored policy list. Null means no per-token limit; an unreadable
    /// value is treated as an empty list, which admits nothing.
    /// </summary>
    public static IReadOnlyList<string>? ReadList(string? json)
    {
        if (json is null)
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<string[]>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static string? WriteList(IReadOnlyCollection<string>? values) =>
        values is { Count: > 0 }
            ? JsonSerializer.Serialize(values.Distinct(StringComparer.Ordinal).ToArray())
            : null;

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
