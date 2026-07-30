using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Permissions;

namespace Sufficit.Identity.Server.Management;

/// <summary>
/// Sufficit composition adapter for contextual permission delegation. It
/// reuses the persisted directive claims that feed runtime authorization and
/// never introduces a second permission store.
/// </summary>
public sealed class SufficitDirectiveUserPermissionStore(
    AppDbContext database,
    UserManager<ApplicationUser> userManager)
    : IManagementContextualPermissionStore
{
    private const string DirectiveClaimType = "directive";

    public async Task<IReadOnlyList<ManagementContextualPermissionDescriptor>>
        ListKnownAsync(CancellationToken cancellationToken = default)
    {
        var values = await database.UserClaims
            .AsNoTracking()
            .Where(claim =>
                claim.ClaimType == DirectiveClaimType
                && claim.ClaimValue != null)
            .Select(claim => claim.ClaimValue!)
            .ToArrayAsync(cancellationToken);

        return values
            .SelectMany(
                SufficitDirectiveManagementEntitlementResolver.DirectiveValues)
            .Select(TryParse)
            .Where(directive => directive is not null)
            .Select(directive => directive!.Value.Key)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .Select(key => new ManagementContextualPermissionDescriptor(
                key,
                key,
                "Diretiva Sufficit no contexto selecionado"))
            .ToArray();
    }

    public async Task<IReadOnlySet<string>> ListAssignedKeysAsync(
        string userId,
        string contextId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        var normalizedContextId = NormalizeContext(contextId);
        var values = await DirectiveClaimValuesAsync(
            userId,
            cancellationToken);

        return KeysForContext(values, normalizedContextId);
    }

    public async Task<IReadOnlySet<string>> ListDelegableKeysAsync(
        string operatorUserId,
        string contextId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operatorUserId);
        var normalizedContextId = NormalizeContext(contextId);
        var values = await DirectiveClaimValuesAsync(
            operatorUserId,
            cancellationToken);

        // Exact-context only. A Guid.Empty wildcard never becomes delegable by
        // a Manager, even though legacy authorization can treat it globally.
        return KeysForContext(values, normalizedContextId);
    }

    public async Task SetAsync(
        string userId,
        string key,
        string contextId,
        bool assigned,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        var normalizedKey = NormalizeKey(key);
        var normalizedContextId = NormalizeContext(contextId);
        var value = $"{normalizedKey}:{normalizedContextId}";
        var user = await userManager.FindByIdAsync(userId)
            ?? throw new InvalidOperationException(
                "The user no longer exists while changing a directive.");
        var claims = await userManager.GetClaimsAsync(user);
        var directiveClaims = claims
            .Where(claim => string.Equals(
                claim.Type,
                DirectiveClaimType,
                StringComparison.Ordinal))
            .ToArray();
        var alreadyAssigned = directiveClaims.Any(claim =>
            SufficitDirectiveManagementEntitlementResolver
                .DirectiveValues(claim.Value)
                .Any(candidate => IsExact(
                    candidate,
                    normalizedKey,
                    normalizedContextId)));

        if (alreadyAssigned == assigned)
        {
            return;
        }

        if (assigned)
        {
            EnsureSucceeded(await userManager.AddClaimAsync(
                user,
                new Claim(DirectiveClaimType, value)));
            return;
        }

        foreach (var claim in directiveClaims)
        {
            var currentValues =
                SufficitDirectiveManagementEntitlementResolver
                    .DirectiveValues(claim.Value)
                    .ToArray();
            if (!currentValues.Any(candidate => IsExact(
                    candidate,
                    normalizedKey,
                    normalizedContextId)))
            {
                continue;
            }

            var remaining = currentValues
                .Where(candidate => !IsExact(
                    candidate,
                    normalizedKey,
                    normalizedContextId))
                .ToArray();
            if (remaining.Length is 0)
            {
                EnsureSucceeded(await userManager.RemoveClaimAsync(
                    user,
                    claim));
            }
            else
            {
                EnsureSucceeded(await userManager.ReplaceClaimAsync(
                    user,
                    claim,
                    new Claim(
                        DirectiveClaimType,
                        JsonSerializer.Serialize(remaining))));
            }
        }
    }

    private async Task<string[]> DirectiveClaimValuesAsync(
        string userId,
        CancellationToken cancellationToken) =>
        await database.UserClaims
            .AsNoTracking()
            .Where(claim =>
                claim.UserId == userId
                && claim.ClaimType == DirectiveClaimType
                && claim.ClaimValue != null)
            .Select(claim => claim.ClaimValue!)
            .ToArrayAsync(cancellationToken);

    private static IReadOnlySet<string> KeysForContext(
        IEnumerable<string> claimValues,
        string contextId) =>
        claimValues
            .SelectMany(
                SufficitDirectiveManagementEntitlementResolver.DirectiveValues)
            .Select(TryParse)
            .Where(directive =>
                directive is not null
                && string.Equals(
                    directive.Value.ContextId,
                    contextId,
                    StringComparison.OrdinalIgnoreCase))
            .Select(directive => directive!.Value.Key)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    private static bool IsExact(
        string value,
        string key,
        string contextId)
    {
        var directive = TryParse(value);
        return directive is not null
            && string.Equals(
                directive.Value.Key,
                key,
                StringComparison.OrdinalIgnoreCase)
            && string.Equals(
                directive.Value.ContextId,
                contextId,
                StringComparison.OrdinalIgnoreCase);
    }

    private static (string Key, string ContextId)? TryParse(string value)
    {
        var separator = value.LastIndexOf(':');
        if (separator <= 0 || separator == value.Length - 1)
        {
            return null;
        }

        var key = value[..separator].Trim().ToLowerInvariant();
        if (!IsValidKey(key)
            || !Guid.TryParse(value[(separator + 1)..], out var contextId))
        {
            return null;
        }

        return (key, contextId.ToString("D"));
    }

    private static string NormalizeKey(string key)
    {
        var normalized = key?.Trim().ToLowerInvariant();
        if (!IsValidKey(normalized))
        {
            throw new ArgumentException(
                "A valid Sufficit directive key is required.",
                nameof(key));
        }

        return normalized!;
    }

    private static bool IsValidKey(string? key) =>
        !string.IsNullOrWhiteSpace(key)
        && key.Length <= 100
        && key.All(character =>
            char.IsAsciiLetterOrDigit(character)
            || character is '.' or '-' or '_');

    private static string NormalizeContext(string contextId)
    {
        if (!Guid.TryParse(contextId?.Trim(), out var parsed)
            || parsed == Guid.Empty)
        {
            throw new ArgumentException(
                "A non-empty Sufficit ContextId is required.",
                nameof(contextId));
        }

        return parsed.ToString("D");
    }

    private static void EnsureSucceeded(IdentityResult result)
    {
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                string.Join(
                    ' ',
                    result.Errors.Select(error => error.Code)));
        }
    }
}
