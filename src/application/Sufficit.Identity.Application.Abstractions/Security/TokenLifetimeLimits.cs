namespace Sufficit.Identity.Application.Security;

/// <summary>
/// Shared bounds for OAuth/OIDC token lifetime overrides exposed by the
/// management and deployment surfaces.
/// </summary>
public static class TokenLifetimeLimits
{
    public const int MinimumAccessTokenLifetimeMinutes = 1;
    public const int MaximumAccessTokenLifetimeMinutes = 7 * 24 * 60;
    public const int MinimumIdentityTokenLifetimeMinutes = 1;
    public const int MaximumIdentityTokenLifetimeMinutes = 120;
    public const int MinimumRefreshTokenLifetimeDays = 1;
    public const int MaximumRefreshTokenLifetimeDays = 365;
}
