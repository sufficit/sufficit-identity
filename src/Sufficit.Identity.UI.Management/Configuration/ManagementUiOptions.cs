using Microsoft.AspNetCore.Http;

namespace Sufficit.Identity.UI.Management.Configuration;

public sealed class ManagementUiOptions
{
    public const string SectionName = "Sufficit:Identity:ManagementUI";

    public string PathBase { get; set; } = "management";

    public ManagementUiAuthorizationOptions Authorization { get; set; } = new();

    public PathString GetPathBase()
    {
        var path = PathBase?.Trim().Trim('/');
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new InvalidOperationException(
                $"{SectionName}:PathBase must identify a non-root path.");
        }

        return new PathString($"/{path}");
    }

    public string GetBaseHref() => $"{GetPathBase()}/";

    public string[] GetManagerRoles() =>
        NormalizeRoles(Authorization.ManagerRoles, "manager");

    public string[] GetAccessRoles(IEnumerable<string> administratorRoles) =>
        administratorRoles
            .Concat(GetManagerRoles())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static string[] NormalizeRoles(string[]? roles, string fallback)
    {
        var normalized = (roles ?? [])
            .Where(role => !string.IsNullOrWhiteSpace(role))
            .Select(role => role.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return normalized.Length is 0 ? [fallback] : normalized;
    }
}

public sealed class ManagementUiAuthorizationOptions
{
    public string[] ManagerRoles { get; set; } = ["manager"];
}
