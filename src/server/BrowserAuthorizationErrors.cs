using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Diagnostics;
using Sufficit.Identity.UI.Components;

namespace Sufficit.Identity.Server;

/// <summary>Presentation only: never changes protocol validation or follows an untrusted return URL.</summary>
public static class BrowserAuthorizationErrors
{
    public static IApplicationBuilder UseBrowserAuthorizationErrors(this IApplicationBuilder app)
        => app.UseWhen(context => IsHtmlNavigation(context.Request), branch =>
            branch.UseStatusCodePages(async (StatusCodeContext status) =>
            {
                var context = status.HttpContext;
                var response = context.GetOpenIddictServerResponse();
                if (string.IsNullOrEmpty(response?.Error))
                    return;

                context.Response.Headers.CacheControl = "no-store";
                context.Response.Headers.Pragma = "no-cache";
                context.Response.Headers["Referrer-Policy"] = "no-referrer";
                // Do not reflect error_description, request_uri, redirect_uri or other
                // request data. A replayed/expired request must stay invalid.
                await new RazorComponentResult<AuthorizationError>
                {
                    StatusCode = context.Response.StatusCode,
                    PreventStreamingRendering = true
                }.ExecuteAsync(context);
            }));

    internal static bool IsHtmlNavigation(HttpRequest request)
        => STS.ErrorPages.BrowserNavigationRequest.IsHtmlNavigation(request);
}
