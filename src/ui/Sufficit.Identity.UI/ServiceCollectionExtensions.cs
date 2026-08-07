using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Localization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sufficit.Identity.UI.Abstractions.Hosting;
using Sufficit.Identity.UI.Services;

namespace Sufficit.Identity.UI;

/// <summary>
/// DI and pipeline extensions to inject the Sufficit Identity UI (Blazor Server)
/// into an authorization-server host.
/// </summary>
public static class ServiceCollectionExtensions
{
    private static readonly HashSet<string> SupportedCultures =
        new(StringComparer.OrdinalIgnoreCase) { "pt-BR", "en-US" };

    /// <summary>
    /// Registers the Blazor Server components and supporting services for the
    /// Identity UI (login, consent, logout, device flow, manage area).
    /// </summary>
    public static IServiceCollection AddSufficitIdentityUI(
        this IServiceCollection services,
        IConfiguration? configuration = null)
    {
        // Phase 2: carry the module descriptor through DI for startup validation.
        services.TryAddSingleton<UiModuleRegistry>();
        services.TryAddSingleton<IUiModuleRegistry>(sp => sp.GetRequiredService<UiModuleRegistry>());
        services.AddSingleton(_ => new UiModuleDescriptor(
            "sufficit-identity-ui", UiSurface.Public, new Version(0, 4, 0), new Version(0, 4, 0)));

        services.AddHttpContextAccessor();
        services.AddScoped<ScopeViewModelProvider>();

        // i18n: IStringLocalizer<SharedResource> (resx-backed, pt-BR default).
        services.AddLocalization();

        services.AddRazorComponents()
                .AddInteractiveServerComponents();

        services.AddAntiforgery();

        return services;
    }

    /// <summary>
    /// Maps the Blazor Server endpoints and static assets into the STS pipeline.
    /// Must be called AFTER <c>UseAuthentication</c> / <c>UseAuthorization</c> /
    /// <c>UseRouting</c> and BEFORE the catch-all fallback.
    /// </summary>
    public static IApplicationBuilder UseSufficitIdentityUI(this WebApplication app)
    {
        app.UseAntiforgery();

        // Redirect /favicon.ico to the real asset so browsers that auto-request
        // the root favicon don't get a 404.
        app.MapGet("/favicon.ico", () => Results.Redirect(
            "/_content/Sufficit.Identity.UI/img/favicon.png", permanent: true));

        app.MapGet("/culture/set", (
            HttpContext context,
            string? culture,
            string? returnUrl) =>
        {
            var selectedCulture = SupportedCultures.Contains(culture ?? string.Empty)
                ? culture!
                : "pt-BR";

            context.Response.Cookies.Append(
                CookieRequestCultureProvider.DefaultCookieName,
                CookieRequestCultureProvider.MakeCookieValue(
                    new RequestCulture(selectedCulture)),
                new CookieOptions
                {
                    Expires = DateTimeOffset.UtcNow.AddYears(1),
                    IsEssential = true,
                    SameSite = SameSiteMode.Lax,
                    Secure = context.Request.IsHttps,
                    Path = "/",
                });

            return Results.Redirect(GetSafeLocalReturnUrl(returnUrl));
        }).ExcludeFromDescription();

        app.MapStaticAssets();
        app.MapRazorComponents<Components.App>()
           .AddInteractiveServerRenderMode();

        return app;
    }

    private static string GetSafeLocalReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl)
            || returnUrl[0] != '/'
            || (returnUrl.Length > 1 && returnUrl[1] is '/' or '\\'))
        {
            return "/";
        }

        return returnUrl;
    }
}
