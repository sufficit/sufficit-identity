using Microsoft.AspNetCore.Components;

namespace Sufficit.Identity.UI.Management.OperatorTokens;

/// <summary>
/// Produces the canonical, shareable URL for an operator-token request while
/// preserving unrelated query parameters such as the selected UI culture.
/// </summary>
public static class OperatorTokenRequestUrl
{
    public static string Build(
        NavigationManager navigation,
        string? purpose,
        int lifetimeSeconds,
        IEnumerable<string> capabilities)
    {
        ArgumentNullException.ThrowIfNull(navigation);
        ArgumentNullException.ThrowIfNull(capabilities);

        var normalizedCapabilities = capabilities
            .Where(capability => !string.IsNullOrWhiteSpace(capability))
            .Select(capability => capability.Trim())
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();

        return navigation.GetUriWithQueryParameters(
            new Dictionary<string, object?>
            {
                ["action"] = "issue",
                ["purpose"] = string.IsNullOrWhiteSpace(purpose)
                    ? null
                    : purpose.Trim(),
                ["lifetimeSeconds"] = lifetimeSeconds,
                ["capability"] = normalizedCapabilities.Length is 0
                    ? null
                    : normalizedCapabilities,
                // Normalize the supported CSV alias away. Keeping both forms
                // would make an unchecked item reappear after a shared reload.
                ["capabilities"] = null,
            });
    }
}
