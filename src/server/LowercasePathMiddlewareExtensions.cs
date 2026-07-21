using Microsoft.AspNetCore.Builder;

namespace Sufficit.Identity.Server;

/// <summary>
/// Extension methods for registering <see cref="LowercasePathMiddleware"/>.
/// </summary>
public static class LowercasePathMiddlewareExtensions
{
    /// <summary>
    /// Registers the lowercase-path canonicalization middleware in the
    /// pipeline. Must be placed BEFORE <c>UseAuthentication</c>,
    /// <c>UseAuthorization</c>, <c>MapControllers</c> and any endpoint
    /// mapping (Razor Components, OpenIddict handlers) so the redirect
    /// happens before any component tries to match the URL.
    /// </summary>
    public static IApplicationBuilder UseLowercasePaths(this IApplicationBuilder app)
        => app.UseMiddleware<LowercasePathMiddleware>();
}
