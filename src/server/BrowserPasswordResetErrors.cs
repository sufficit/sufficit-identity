using Microsoft.AspNetCore.Http.HttpResults;
using Sufficit.Identity.STS.ErrorPages;
using Sufficit.Identity.UI.Components;

namespace Sufficit.Identity.Server;

internal static class BrowserPasswordResetErrors
{
    internal static IApplicationBuilder UseBrowserPasswordResetErrors(this IApplicationBuilder app)
        => app.UseWhen(context => IsResetNavigation(context.Request), branch =>
            branch.Use(next => async context =>
            {
                await next(context);

                var response = context.Response;
                // Blazor can set the HTML content type before rejecting a form
                // without writing a body. StatusCodePages skips such responses.
                if (response.HasStarted || response.StatusCode != StatusCodes.Status400BadRequest
                    || response.ContentLength is > 0)
                    return;

                // The Razor result sets this header itself after the endpoint
                // has already set it, even on an early validation failure.
                response.Headers.Remove("blazor-enhanced-nav");
                response.ContentLength = null;
                response.Headers.CacheControl = "no-store";
                response.Headers["Referrer-Policy"] = "no-referrer";
                await new RazorComponentResult<AuthorizationError>(new { PasswordResetRejected = true })
                {
                    StatusCode = StatusCodes.Status400BadRequest,
                    PreventStreamingRendering = true
                }.ExecuteAsync(context);
            }));

    private static bool IsResetNavigation(HttpRequest request)
        => (HttpMethods.IsGet(request.Method) || HttpMethods.IsPost(request.Method))
            && (request.Path.Equals("/account/resetpassword", StringComparison.OrdinalIgnoreCase)
                || request.Path.Equals("/account/resetpassword/", StringComparison.OrdinalIgnoreCase))
            && BrowserNavigationRequest.PrefersHtmlDocument(request);
}
