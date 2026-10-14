using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Diagnostics;
using Sufficit.Identity.UI.Components;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Sufficit.Identity.STS.Controllers;

namespace Sufficit.Identity.Server;

/// <summary>Presentation only: never changes protocol validation or follows an untrusted return URL.</summary>
public static class BrowserAuthorizationErrors
{
    public static IServiceCollection AddBrowserAuthorizationErrors(this IServiceCollection services)
    {
        services.Configure<MvcOptions>(options => options.Filters.Add<DeviceErrorPresentationFilter>());
        return services;
    }

    // DeviceController also returns local protocol errors as MVC results rather
    // than OpenIddict responses. Status pages cannot replace an already-written JSON body.
    private sealed class DeviceErrorPresentationFilter : IAsyncAlwaysRunResultFilter
    {
        public async Task OnResultExecutionAsync(ResultExecutingContext context, ResultExecutionDelegate next)
        {
            if (context.Controller is DeviceController
                && context.Result is BadRequestObjectResult
                && STS.ErrorPages.BrowserNavigationRequest.IsHtmlNavigation(context.HttpContext.Request))
            {
                context.Cancel = true;
                await WritePageAsync(context.HttpContext, StatusCodes.Status400BadRequest);
                return;
            }
            await next();
        }
    }

    private static async Task WritePageAsync(HttpContext context, int statusCode)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
        context.Response.Headers["Referrer-Policy"] = "no-referrer";
        await new RazorComponentResult<AuthorizationError>
        {
            StatusCode = statusCode,
            PreventStreamingRendering = true
        }.ExecuteAsync(context);
    }

    public static IApplicationBuilder UseBrowserAuthorizationErrors(this IApplicationBuilder app)
        => app.UseWhen(context => IsHtmlNavigation(context.Request), branch =>
            branch.UseStatusCodePages(async (StatusCodeContext status) =>
            {
                var context = status.HttpContext;
                var response = context.GetOpenIddictServerResponse();
                if (string.IsNullOrEmpty(response?.Error))
                    return;

                // Never reflect protocol descriptions, codes or return URLs.
                await WritePageAsync(context, context.Response.StatusCode);
            }));

    internal static bool IsHtmlNavigation(HttpRequest request)
        => STS.ErrorPages.BrowserNavigationRequest.IsHtmlNavigation(request);
}
