using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Services;

namespace Sufficit.Identity.STS;

/// <summary>Guides a recovered browser session back to enrollment, without interfering with assets or its Blazor circuit.</summary>
public sealed class MfaRecoveryNavigationMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context, AppDbContext database)
    {
        var path = context.Request.Path;
        var isPage = HttpMethods.IsGet(context.Request.Method)
            && context.Request.Headers.Accept.Any(value => value?.Contains("text/html", StringComparison.OrdinalIgnoreCase) == true);
        if (isPage && context.User.Identity?.IsAuthenticated == true
            && !path.StartsWithSegments("/manage/twofactor", StringComparison.OrdinalIgnoreCase)
            && !path.StartsWithSegments("/account/logout", StringComparison.OrdinalIgnoreCase)
            // Protocol endpoints decide between an interactive redirect and
            // an OAuth error (notably prompt=none) in their own handlers.
            && !path.StartsWithSegments("/connect", StringComparison.OrdinalIgnoreCase)
            && !path.StartsWithSegments("/account/reauthenticate", StringComparison.OrdinalIgnoreCase)
            && !path.StartsWithSegments("/account/loginwith2fa", StringComparison.OrdinalIgnoreCase)
            && !path.StartsWithSegments("/_blazor", StringComparison.OrdinalIgnoreCase)
            && !Path.HasExtension(path.Value))
        {
            var subject = context.User.FindFirstValue(ClaimTypes.NameIdentifier)
                ?? context.User.FindFirstValue("sub");
            if (subject is not null && await MfaRecoveryState.IsRequiredAsync(database, subject, context.RequestAborted))
            {
                context.Response.Redirect("/manage/twofactor");
                return;
            }
        }
        await next(context);
    }
}
