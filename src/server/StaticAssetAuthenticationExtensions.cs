using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.StaticAssets;

namespace Sufficit.Identity.Server;

/// <summary>
/// Authentication placement that leaves framework static assets out of the
/// cookie validation path.
/// </summary>
public static class StaticAssetAuthenticationExtensions
{
    /// <summary>
    /// Runs <c>UseAuthentication</c> for every request except those routed to
    /// an endpoint produced by <c>MapStaticAssets</c>. Must be placed after
    /// <c>UseRouting</c> so the selected endpoint is known.
    /// </summary>
    /// <remarks>
    /// Static assets are anonymous, fingerprinted files; authenticating them
    /// only repeated the per-request security-stamp read for every script and
    /// stylesheet of a page. The exclusion keys on the endpoint metadata the
    /// framework attaches to those endpoints, never on the path: requests with
    /// no matched endpoint still authenticate, which matters because OpenIddict
    /// processes its protocol endpoints (<c>/connect/*</c>, discovery) as
    /// authentication request handlers inside the authentication middleware.
    /// </remarks>
    public static IApplicationBuilder UseAuthenticationExceptStaticAssets(
        this IApplicationBuilder app)
    {
        app.UseWhen(
            context => !IsStaticAsset(context),
            branch => branch.UseAuthentication());

        // UseAuthentication records itself in the builder properties, but the
        // UseWhen branch writes to a copy. Without the marker on this builder,
        // WebApplication would insert its own UseAuthentication at the start
        // of the pipeline and authenticate static assets anyway.
        app.Properties[AuthenticationMiddlewareSetKey] = true;
        return app;
    }

    private const string AuthenticationMiddlewareSetKey = "__AuthenticationMiddlewareSet";

    internal static bool IsStaticAsset(HttpContext context) =>
        context.GetEndpoint()?.Metadata.GetMetadata<StaticAssetDescriptor>() is not null;
}
