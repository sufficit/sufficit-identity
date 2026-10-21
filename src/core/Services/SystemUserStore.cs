using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Core.Services;

/// <summary>
/// System users and their one-time enrollment codes. The sign-in manager asks
/// whether a user is a system user; the management service creates, disables
/// and issues codes; the token endpoint redeems codes.
/// </summary>
public sealed class SystemUserStore(
    IDbContextFactory<AppDbContext> databaseFactory,
    TimeProvider? timeProvider = null)
{
    /// <summary>Marks the value as an enrollment code in logs and scanners.</summary>
    public const string CodePrefix = "sys_enroll_";

    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public DateTime UtcNow => _timeProvider.GetUtcNow().UtcDateTime;

    public async Task<SystemUser?> FindAsync(
        string userId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId))
        {
            return null;
        }

        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        return await database.SystemUsers
            .AsNoTracking()
            .SingleOrDefaultAsync(x => x.UserId == userId, cancellationToken);
    }

    public async Task<bool> IsSystemUserAsync(
        string userId,
        CancellationToken cancellationToken = default) =>
        await FindAsync(userId, cancellationToken) is not null;

    public async Task<IReadOnlyList<SystemUser>> ListAsync(CancellationToken cancellationToken = default)
    {
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        return await database.SystemUsers
            .AsNoTracking()
            .OrderBy(x => x.CreatedAtUtc)
            .ToListAsync(cancellationToken);
    }

    public async Task AddAsync(SystemUser record, CancellationToken cancellationToken = default)
    {
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        database.SystemUsers.Add(record);
        await database.SaveChangesAsync(cancellationToken);
    }

    /// <summary>Disables or re-enables; returns false when the user is not a system user.</summary>
    public async Task<bool> SetDisabledAsync(
        string userId,
        string? disabledBy,
        CancellationToken cancellationToken = default)
    {
        var now = UtcNow;
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        var affected = await database.SystemUsers
            .Where(x => x.UserId == userId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(x => x.DisabledAtUtc, disabledBy is null ? null : now)
                .SetProperty(x => x.DisabledBy, disabledBy),
                cancellationToken);
        return affected == 1;
    }

    /// <summary>
    /// Creates an enrollment code and its record. The plaintext code is
    /// returned once and never stored.
    /// </summary>
    public static (SystemUserEnrollment Record, string Code) CreateEnrollment(
        string userId,
        string clientId,
        string label,
        string issuedBy,
        DateTime createdAtUtc,
        TimeSpan lifetime)
    {
        var code = CodePrefix + Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        var hash = Hash(code);
        return (new SystemUserEnrollment
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ClientId = clientId,
            Label = label,
            CodeHash = hash,
            CodeHint = hash[..IdentityDatabaseSchema.SystemUserEnrollmentHintLength],
            IssuedBy = issuedBy,
            CreatedAtUtc = createdAtUtc,
            ExpiresAtUtc = createdAtUtc + lifetime,
        }, code);
    }

    public async Task AddEnrollmentAsync(
        SystemUserEnrollment record,
        CancellationToken cancellationToken = default)
    {
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        database.SystemUserEnrollments.Add(record);
        await database.SaveChangesAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<SystemUserEnrollment>> ListEnrollmentsAsync(
        string userId,
        CancellationToken cancellationToken = default)
    {
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        return await database.SystemUserEnrollments
            .AsNoTracking()
            .Where(x => x.UserId == userId)
            .OrderByDescending(x => x.CreatedAtUtc)
            .ToListAsync(cancellationToken);
    }

    public async Task<SystemUserEnrollment?> FindEnrollmentAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        return await database.SystemUserEnrollments
            .AsNoTracking()
            .SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
    }

    public static string Hash(string code) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(code)));

    public static bool IsRedeemable(SystemUserEnrollment record, DateTime nowUtc) =>
        record.RevokedAtUtc is null
        && record.RedeemedAtUtc is null
        && record.ExpiresAtUtc > nowUtc;

    /// <summary>Returns the enrollment when the presented code can be redeemed now.</summary>
    public async Task<SystemUserEnrollment?> FindRedeemableAsync(
        string? code,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(code) || !code.StartsWith(CodePrefix, StringComparison.Ordinal))
        {
            return null;
        }

        var hash = Hash(code);
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        var record = await database.SystemUserEnrollments
            .AsNoTracking()
            .SingleOrDefaultAsync(x => x.CodeHash == hash, cancellationToken);
        return record is not null && IsRedeemable(record, UtcNow) ? record : null;
    }

    /// <summary>
    /// Marks the code redeemed. The conditional update is atomic: of two
    /// concurrent redemptions of one code exactly one succeeds.
    /// </summary>
    public async Task<bool> TryRedeemAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        var now = UtcNow;
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        var affected = await database.SystemUserEnrollments
            .Where(x => x.Id == id
                && x.RevokedAtUtc == null
                && x.RedeemedAtUtc == null
                && x.ExpiresAtUtc > now)
            .ExecuteUpdateAsync(setters => setters.SetProperty(x => x.RedeemedAtUtc, now),
                cancellationToken);
        return affected == 1;
    }

    /// <summary>Links the redeemed code to the authorization that backs the credential.</summary>
    public async Task SetAuthorizationAsync(
        Guid id,
        string authorizationId,
        CancellationToken cancellationToken = default)
    {
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        await database.SystemUserEnrollments
            .Where(x => x.Id == id)
            .ExecuteUpdateAsync(setters => setters.SetProperty(x => x.AuthorizationId, authorizationId),
                cancellationToken);
    }

    /// <summary>Marks the enrollment revoked; returns false when it was already revoked or unknown.</summary>
    public async Task<bool> RevokeEnrollmentAsync(
        Guid id,
        string revokedBy,
        CancellationToken cancellationToken = default)
    {
        var now = UtcNow;
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        var affected = await database.SystemUserEnrollments
            .Where(x => x.Id == id && x.RevokedAtUtc == null)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(x => x.RevokedAtUtc, now)
                .SetProperty(x => x.RevokedBy, revokedBy),
                cancellationToken);
        return affected == 1;
    }
}
