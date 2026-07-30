using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Users;

namespace Sufficit.Identity.Server.Management;

/// <summary>
/// Sufficit user-membership adapter.
/// Existing accounts remain discoverable through persisted directive claims;
/// newly provisioned accounts receive a neutral explicit context claim so
/// creation never delegates authority by accident.
/// </summary>
public sealed class SufficitDirectiveUserContextStore(
    AppDbContext database,
    UserManager<ApplicationUser> userManager,
    IOptions<ManagementOptions> options) : IManagementUserContextStore
{
    private const string DirectiveClaimType = "directive";

    public async Task<IReadOnlySet<string>> ListKnownContextIdsAsync(
        CancellationToken cancellationToken = default)
    {
        var explicitClaimTypes = ExplicitContextClaimTypes();
        var rows = await database.UserClaims
            .AsNoTracking()
            .Where(claim =>
                claim.ClaimType == DirectiveClaimType
                || explicitClaimTypes.Contains(claim.ClaimType!))
            .Select(claim => new { claim.ClaimType, claim.ClaimValue })
            .ToArrayAsync(cancellationToken);

        return rows
            .SelectMany(row => Contexts(row.ClaimType, row.ClaimValue))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    public async Task<IReadOnlySet<string>> ListUserIdsAsync(
        string contextId,
        CancellationToken cancellationToken = default)
    {
        var normalizedContextId = NormalizeRequiredContext(contextId);
        var explicitClaimTypes = ExplicitContextClaimTypes();
        var candidates = await database.UserClaims
            .AsNoTracking()
            .Where(claim =>
                claim.ClaimValue != null
                && (claim.ClaimType == DirectiveClaimType
                    && claim.ClaimValue.Contains(normalizedContextId)
                    || explicitClaimTypes.Contains(claim.ClaimType!)
                    && claim.ClaimValue == normalizedContextId))
            .Select(claim => new
            {
                claim.UserId,
                claim.ClaimType,
                claim.ClaimValue
            })
            .ToArrayAsync(cancellationToken);

        return candidates
            .Where(candidate => Contexts(
                    candidate.ClaimType,
                    candidate.ClaimValue)
                .Contains(
                    normalizedContextId,
                    StringComparer.OrdinalIgnoreCase))
            .Select(candidate => candidate.UserId)
            .ToHashSet(StringComparer.Ordinal);
    }

    public async Task<ManagementUserMembership> GetMembershipAsync(
        string userId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        var explicitClaimTypes = ExplicitContextClaimTypes();
        var values = await database.UserClaims
            .AsNoTracking()
            .Where(claim =>
                claim.UserId == userId
                && (claim.ClaimType == DirectiveClaimType
                    || explicitClaimTypes.Contains(claim.ClaimType!))
                && claim.ClaimValue != null)
            .Select(claim => new { claim.ClaimType, claim.ClaimValue })
            .ToArrayAsync(cancellationToken);
        var contextIds = values
            .SelectMany(value => Contexts(
                value.ClaimType,
                value.ClaimValue))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var hasGlobalScope = values.Any(value =>
            string.Equals(
                value.ClaimType,
                DirectiveClaimType,
                StringComparison.Ordinal)
            && RequiresAdministrator(value.ClaimValue));

        return new ManagementUserMembership(contextIds, hasGlobalScope);
    }

    public async Task<IReadOnlySet<string>> ListContextIdsAsync(
        string userId,
        CancellationToken cancellationToken = default) =>
        (await GetMembershipAsync(userId, cancellationToken)).ContextIds;

    public async Task<bool> UserBelongsToAsync(
        string userId,
        string contextId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        var normalizedContextId = NormalizeRequiredContext(contextId);
        var explicitClaimTypes = ExplicitContextClaimTypes();
        var values = await database.UserClaims
            .AsNoTracking()
            .Where(claim =>
                claim.UserId == userId
                && claim.ClaimValue != null
                && (claim.ClaimType == DirectiveClaimType
                    && claim.ClaimValue.Contains(normalizedContextId)
                    || explicitClaimTypes.Contains(claim.ClaimType!)
                    && claim.ClaimValue == normalizedContextId))
            .Select(claim => new { claim.ClaimType, claim.ClaimValue })
            .ToArrayAsync(cancellationToken);

        return values.Any(value => Contexts(
                value.ClaimType,
                value.ClaimValue)
            .Contains(
                normalizedContextId,
                StringComparer.OrdinalIgnoreCase));
    }

    public async Task AddToContextAsync(
        string userId,
        string contextId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        var normalizedContextId = NormalizeRequiredContext(contextId);
        var claimType = ExplicitContextClaimTypes()[0];
        var user = await userManager.FindByIdAsync(userId)
            ?? throw new InvalidOperationException(
                "The user no longer exists while assigning its context.");
        var claims = await userManager.GetClaimsAsync(user);
        if (claims.Any(claim =>
            string.Equals(
                claim.Type,
                claimType,
                StringComparison.OrdinalIgnoreCase)
            && string.Equals(
                claim.Value,
                normalizedContextId,
                StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        var result = await userManager.AddClaimAsync(
            user,
            new Claim(claimType, normalizedContextId));
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                "The user context association could not be persisted.");
        }
    }

    private IEnumerable<string> Contexts(
        string? claimType,
        string? value)
    {
        if (string.Equals(
            claimType,
            DirectiveClaimType,
            StringComparison.Ordinal))
        {
            return SufficitDirectiveManagementEntitlementResolver
                .DirectiveValues(value)
                .Select(
                    SufficitDirectiveManagementEntitlementResolver
                        .ParseContextId)
                .Where(context => context is not null)
                .Select(context => context!);
        }

        if (!ExplicitContextClaimTypes().Contains(
            claimType ?? string.Empty,
            StringComparer.OrdinalIgnoreCase))
        {
            return [];
        }

        var normalized = Guid.TryParse(value?.Trim(), out var contextId)
            && contextId != Guid.Empty
                ? contextId.ToString("D")
                : null;
        return normalized is null ? [] : [normalized];
    }

    private string[] ExplicitContextClaimTypes()
    {
        var configured = options.Value.Authorization.ContextClaimTypes
            .Where(type => !string.IsNullOrWhiteSpace(type))
            .Select(type => type.Trim())
            .Where(type => !string.Equals(
                type,
                DirectiveClaimType,
                StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return configured.Length is 0 ? ["management_context"] : configured;
    }

    private static bool RequiresAdministrator(string? claimValue)
    {
        var directives = SufficitDirectiveManagementEntitlementResolver
            .DirectiveValues(claimValue)
            .ToArray();
        return directives.Length is 0
            || directives.Any(directive =>
                SufficitDirectiveManagementEntitlementResolver
                    .ParseContextId(directive) is null);
    }

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
