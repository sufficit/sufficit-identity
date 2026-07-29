using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Users;

namespace Sufficit.Identity.Server.Management;

/// <summary>
/// Resolves Sufficit user membership from persisted directive claims.
/// A claim grants membership only in the exact ContextId encoded in one of
/// its key:ContextId values; malformed values and Guid.Empty fail closed.
/// </summary>
public sealed class SufficitDirectiveUserContextStore(
    AppDbContext database) : IManagementUserContextStore
{
    private const string DirectiveClaimType = "directive";

    public async Task<IReadOnlySet<string>> ListUserIdsAsync(
        string contextId,
        CancellationToken cancellationToken = default)
    {
        var normalizedContextId = NormalizeRequiredContext(contextId);
        var candidates = await database.UserClaims
            .AsNoTracking()
            .Where(claim =>
                claim.ClaimType == DirectiveClaimType
                && claim.ClaimValue != null
                && claim.ClaimValue.Contains(normalizedContextId))
            .Select(claim => new { claim.UserId, claim.ClaimValue })
            .ToArrayAsync(cancellationToken);

        return candidates
            .Where(candidate => ContainsContext(
                candidate.ClaimValue,
                normalizedContextId))
            .Select(candidate => candidate.UserId)
            .ToHashSet(StringComparer.Ordinal);
    }

    public async Task<IReadOnlySet<string>> ListContextIdsAsync(
        string userId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        var values = await database.UserClaims
            .AsNoTracking()
            .Where(claim =>
                claim.UserId == userId
                && claim.ClaimType == DirectiveClaimType
                && claim.ClaimValue != null)
            .Select(claim => claim.ClaimValue!)
            .ToArrayAsync(cancellationToken);

        return values
            .SelectMany(
                SufficitDirectiveManagementEntitlementResolver.DirectiveValues)
            .Select(
                SufficitDirectiveManagementEntitlementResolver.ParseContextId)
            .Where(context => context is not null)
            .Select(context => context!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    public async Task<bool> UserBelongsToAsync(
        string userId,
        string contextId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        var normalizedContextId = NormalizeRequiredContext(contextId);
        var values = await database.UserClaims
            .AsNoTracking()
            .Where(claim =>
                claim.UserId == userId
                && claim.ClaimType == DirectiveClaimType
                && claim.ClaimValue != null
                && claim.ClaimValue.Contains(normalizedContextId))
            .Select(claim => claim.ClaimValue!)
            .ToArrayAsync(cancellationToken);

        return values.Any(value => ContainsContext(
            value,
            normalizedContextId));
    }

    private static bool ContainsContext(
        string? value,
        string normalizedContextId) =>
        SufficitDirectiveManagementEntitlementResolver.DirectiveValues(value)
            .Select(
                SufficitDirectiveManagementEntitlementResolver.ParseContextId)
            .Any(context => string.Equals(
                context,
                normalizedContextId,
                StringComparison.OrdinalIgnoreCase));

    private static string NormalizeRequiredContext(string contextId)
    {
        if (!Guid.TryParse(contextId, out var parsed)
            || parsed == Guid.Empty)
        {
            throw new ArgumentException(
                "A non-empty Sufficit ContextId is required.",
                nameof(contextId));
        }

        return parsed.ToString("D");
    }
}
