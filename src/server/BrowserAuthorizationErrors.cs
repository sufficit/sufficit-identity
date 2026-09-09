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
    {
        // Token, PAR, introspection and all other APIs remain machine-readable,
        // even if a caller sends browser-like headers. Only GET navigations qualify.
        if (!HttpMethods.IsGet(request.Method)
            || !(request.Path.Equals("/connect/authorize", StringComparison.OrdinalIgnoreCase)
                || request.Path.Equals("/connect/endsession", StringComparison.OrdinalIgnoreCase)))
            return false;

        var mode = request.Headers["Sec-Fetch-Mode"].ToString();
        var destination = request.Headers["Sec-Fetch-Dest"].ToString();
        if ((mode.Length > 0 && mode != "navigate")
            || (destination.Length > 0 && destination != "document")
            || request.Headers.ContainsKey("X-Requested-With"))
            return false;

        // Legacy browsers may omit Fetch Metadata. An explicit HTML Accept is
        // still required; wildcard, missing, malformed or q=0 is not sufficient.
        try
        {
            var accept = request.GetTypedHeaders().Accept;
            var html = accept?.Where(value => value.MediaType.Equals("text/html", StringComparison.OrdinalIgnoreCase))
                .Select(value => value.Quality ?? 1).DefaultIfEmpty(0).Max() ?? 0;
            var json = accept?.Where(value => value.MediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase))
                .Select(value => value.Quality ?? 1).DefaultIfEmpty(0).Max() ?? 0;
            return html > 0 && html > json;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
