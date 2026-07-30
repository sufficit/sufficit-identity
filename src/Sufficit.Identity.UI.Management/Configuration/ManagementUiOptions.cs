using Microsoft.AspNetCore.Http;

namespace Sufficit.Identity.UI.Management.Configuration;

public sealed class ManagementUiOptions
{
    public const string SectionName = "Sufficit:Identity:ManagementUI";

    public string PathBase { get; set; } = "management";

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
}
