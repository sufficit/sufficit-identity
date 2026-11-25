using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Management.Vault;

namespace Sufficit.Identity.UI.Vault.Data;

internal static class PersonalVaultRevealEndpoint
{
    private const string Path = "/vault/reveal";
    private const string CookieName = "__Secure-Sufficit.Vault.Reveal";

    internal static void MapPersonalVaultReveal(this IEndpointRouteBuilder endpoints) =>
        endpoints.MapPost(Path, RevealAsync)
            .ExcludeFromDescription()
            .WithMetadata(new RequestSizeLimitAttribute(4096))
            .RequireAuthorization(new AuthorizeAttribute(VaultUiPolicies.User)
            {
                AuthenticationSchemes = IdentityConstants.ApplicationScheme
            });

    private static async Task<IResult> RevealAsync(HttpContext context, IAntiforgery antiforgery)
    {
        context.Response.Headers.CacheControl = "no-store";
        if (!context.Request.HasFormContentType || !await antiforgery.IsRequestValidAsync(context))
            return Results.BadRequest();

        var service = context.RequestServices.GetService<IPersonalVaultReveal>();
        if (service is null)
            return Results.Json(new { status = nameof(PersonalVaultRevealStatus.Unavailable) });

        var form = await context.Request.ReadFormAsync(context.RequestAborted);
        var result = await service.RevealAsync(context.User, form["name"].ToString(),
            form["code"].ToString(), context.Request.Cookies[CookieName], context.RequestAborted);
        if (result.Grant is { } grant)
        {
            context.Response.Cookies.Append(CookieName, grant, new CookieOptions
            {
                Path = Path,
                MaxAge = result.Remaining,
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict
            });
        }

        return Results.Json(new
        {
            status = result.Status.ToString(),
            value = result.Value,
            remainingMs = (long)result.Remaining.TotalMilliseconds
        });
    }
}
