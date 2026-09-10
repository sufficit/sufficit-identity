using Microsoft.AspNetCore.Http.HttpResults;
using Sufficit.Identity.UI.Components;

namespace Sufficit.Identity.Server;

internal static class DeviceBrowserLaunch
{
    internal static IEndpointConventionBuilder MapDeviceBrowserLaunch(this IEndpointRouteBuilder app)
        => app.MapGet("/device/launch", (HttpContext context) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.Pragma = "no-cache";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            // Same-origin launcher and popup must use matching policies. No global relaxation.
            context.Response.Headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups";
            var code = context.Request.Query["user_code"].ToString();
            if (code.Length is < 1 or > 64 || code.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-' && c != ' '))
                return (IResult)Results.BadRequest();
            return new RazorComponentResult<DeviceBrowserLauncher>(new { UserCode = code })
            {
                PreventStreamingRendering = true
            };
        }).AllowAnonymous();
}
