using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Management API configuration (opt-in).
/// </summary>
public sealed class ManagementOptions
{
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// Image origins (scheme + host, no path) the console may load user avatars
    /// from. Mirrors the property of the same name on the management module's
    /// own options class: both bind the <c>Sufficit:Identity:Management</c>
    /// section, so they read one setting and cannot disagree.
    /// </summary>
    /// <remarks>
    /// Read here to compose the Content-Security-Policy <c>img-src</c>
    /// directive. Empty by default: no avatar is fetched from anywhere until a
    /// deployment names the origin, and the console shows initials instead.
    /// </remarks>
    public string[] AvatarPictureOrigins { get; init; } = [];

    /// <summary>
    /// Route prefix for the management REST endpoints.
    /// </summary>
    public string RoutePrefix { get; init; } = "api";

    /// <summary>
    /// If true, the management endpoints require an access token carrying the
    /// <c>identity.management</c> scope (or another configured scope).
    /// </summary>
    public bool RequireAuthorization { get; init; } = true;

    /// <summary>
    /// Required authorization policy/scope. Defaults to
    /// <c>identity.management</c>.
    /// </summary>
    public string RequiredScope { get; init; } = "identity.management";
}
