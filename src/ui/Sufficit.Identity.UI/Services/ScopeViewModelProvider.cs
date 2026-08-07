using Microsoft.Extensions.Localization;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.UI.Resources;

namespace Sufficit.Identity.UI.Services;

/// <summary>
/// Builds friendly display models for the scopes requested in an
/// authorization/consent flow. Translates raw scope names into human-readable
/// descriptions (pt-BR) and groups them by identity vs API scope.
/// </summary>
public sealed class ScopeViewModelProvider(
    IStringLocalizer<SharedResource> localizer)
{
    /// <summary>Static display info for standard OIDC scopes.</summary>
    private static readonly HashSet<string> StandardScopes = new(
        ["openid", "profile", "email", "roles", "address", "phone", "offline_access"],
        StringComparer.Ordinal);

    public IReadOnlyList<ScopeViewModel> Build(IEnumerable<string> scopes)
        => Build(scopes.Select(scope =>
            new AuthorizationScopePresentation(scope, null, null, [])));

    public IReadOnlyList<ScopeViewModel> Build(
        IEnumerable<AuthorizationScopePresentation> scopes)
    {
        var list = new List<ScopeViewModel>();
        foreach (var scope in scopes.OrderBy(scope => scope.Name, StringComparer.Ordinal))
        {
            var (displayName, description, isTechnical) = Resolve(scope);
            list.Add(new ScopeViewModel(
                scope.Name,
                displayName,
                description,
                isTechnical));
        }
        return list;
    }

    private (string DisplayName, string Description, bool IsTechnical) Resolve(
        AuthorizationScopePresentation scope)
    {
        if (StandardScopes.Contains(scope.Name))
        {
            var displayName = localizer[$"Scope.{scope.Name}.Name"];
            var standardDescription = localizer[$"Scope.{scope.Name}.Description"];
            return (
                displayName.ResourceNotFound ? scope.Name : displayName.Value,
                standardDescription.ResourceNotFound
                    ? localizer["Scope.StandardDescription"].Value
                    : standardDescription.Value,
                false);
        }

        var hasFriendlyName = !string.IsNullOrWhiteSpace(scope.DisplayName)
            && !string.Equals(
                scope.DisplayName,
                scope.Name,
                StringComparison.OrdinalIgnoreCase);
        var customDescription = string.IsNullOrWhiteSpace(scope.Description)
            ? localizer["Scope.TechnicalDescription", scope.Name].Value
            : scope.Description;
        return (
            hasFriendlyName
                ? scope.DisplayName!
                : localizer["Scope.TechnicalName"].Value,
            customDescription,
            !hasFriendlyName);
    }
}

/// <summary>Display model for a single scope in the consent screen.</summary>
public sealed record ScopeViewModel(
    string Name,
    string DisplayName,
    string Description,
    bool IsTechnical);
