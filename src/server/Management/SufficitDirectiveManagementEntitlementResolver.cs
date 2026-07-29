using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Server.Management;

/// <summary>
/// Sufficit composition adapter for contextual management grants.
/// The generic Management assembly never needs to know the directive claim
/// name, its key:ContextId wire format or the Guid.Empty wildcard convention.
/// </summary>
public sealed class SufficitDirectiveManagementEntitlementResolver(
    IOptions<ManagementOptions> options) : IManagementEntitlementResolver
{
    private const string DirectiveClaimType = "directive";

    public ValueTask<ManagementEntitlements> ResolveAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (principal.Identity?.IsAuthenticated is not true)
        {
            return ValueTask.FromResult(Empty());
        }

        var authorization = options.Value.Authorization;
        if (NormalizeRoles(
                authorization.AdministratorRoles,
                "administrator")
            .Any(principal.IsInRole))
        {
            return ValueTask.FromResult(
                new ManagementEntitlements(
                    HasGlobalAdministratorAccess: true,
                    ManagedContextIds: new HashSet<string>(
                        StringComparer.OrdinalIgnoreCase)));
        }

        if (!NormalizeRoles(authorization.ManagerRoles, "manager")
            .Any(principal.IsInRole))
        {
            return ValueTask.FromResult(Empty());
        }

        var contexts = principal.FindAll(DirectiveClaimType)
            .SelectMany(claim => DirectiveValues(claim.Value))
            .Select(ParseContextId)
            .Where(contextId => contextId is not null)
            .Select(contextId => contextId!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        return ValueTask.FromResult(
            new ManagementEntitlements(
                HasGlobalAdministratorAccess: false,
                ManagedContextIds: contexts));
    }

    internal static IEnumerable<string> DirectiveValues(string? value)
    {
        var normalized = value?.Trim();
        if (string.IsNullOrWhiteSpace(normalized))
        {
            yield break;
        }

        if (!normalized.StartsWith('['))
        {
            yield return normalized;
            yield break;
        }

        string[]? values;
        try
        {
            values = JsonSerializer.Deserialize<string[]>(normalized);
        }
        catch (JsonException)
        {
            yield break;
        }

        foreach (var item in values ?? [])
        {
            if (!string.IsNullOrWhiteSpace(item))
            {
                yield return item.Trim();
            }
        }
    }

    internal static string? ParseContextId(string directive)
    {
        var separator = directive.LastIndexOf(':');
        if (separator <= 0 || separator == directive.Length - 1)
        {
            return null;
        }

        return Guid.TryParse(directive[(separator + 1)..], out var contextId)
            && contextId != Guid.Empty
                ? contextId.ToString("D")
                : null;
    }

    private static string[] NormalizeRoles(string[]? roles, string fallback)
    {
        var normalized = (roles ?? [])
            .Where(role => !string.IsNullOrWhiteSpace(role))
            .Select(role => role.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return normalized.Length is 0 ? [fallback] : normalized;
    }

    private static ManagementEntitlements Empty() =>
        new(
            HasGlobalAdministratorAccess: false,
            ManagedContextIds: new HashSet<string>(
                StringComparer.OrdinalIgnoreCase));
}
