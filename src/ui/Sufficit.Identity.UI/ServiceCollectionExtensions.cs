using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core;
using Sufficit.Identity.UI.Services;

namespace Sufficit.Identity.UI;

/// <summary>
/// DI and pipeline extensions to inject the Sufficit Identity UI (Blazor Server)
/// into any OpenIddict-based STS host.
///
/// Usage in the STS Program.cs:
/// <code>
/// builder.Services.AddSufficitIdentityUI();
/// ...
/// app.UseSufficitIdentityUI();
/// </code>
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Blazor Server components and supporting services for the
    /// Identity UI (login, consent, logout, device flow, manage area).
    /// Must be called AFTER <c>AddIdentity</c> and OpenIddict server/validation
    /// are registered by the host.
    /// </summary>
    public static IServiceCollection AddSufficitIdentityUI(
        this IServiceCollection services,
        IConfiguration? configuration = null)
    {
        services.AddHttpContextAccessor();
        services.AddScoped<IOpenIddictRequestAccessor, OpenIddictRequestAccessor>();
        services.AddScoped<ScopeViewModelProvider>();
        services.AddScoped<CallbackUrlBuilder>();

        // Plain HttpClientFactory: used by the device-flow UserCode page to call
        // the STS's own /connect/device/info endpoint (same app/process, but the
        // contract is deliberately an HTTP round trip owned by the STS controller
        // rather than a direct IOpenIddictTokenManager dependency from the UI).
        services.AddHttpClient();

        // EmailOptions: bound from "Sufficit:Identity:Email".
        // Used by ALL senders (Smtp, Logging, RabbitMQ) to redirect outgoing
        // emails to TestEmailAddress when configured (dev/staging safety net).
        var emailOptions = configuration?.GetSection("Sufficit:Identity:Email")
            .Get<EmailOptions>() ?? new EmailOptions();
        services.AddSingleton(emailOptions);

        // RegisterConfiguration: bound from "Sufficit:Identity:Register".
        // Defaults match Sufficit's policy (emails only, no separate username).
        var registerConfig = configuration?.GetSection("Sufficit:Identity:Register")
            .Get<RegisterConfiguration>() ?? new RegisterConfiguration();
        services.AddSingleton(registerConfig);

        // IEmailSender: prefer SMTP when "Sufficit:Identity:Smtp:Host" is set,
        // otherwise fall back to a logging-only sender so that password reset /
        // email confirmation links are visible in the STS console during dev.
        var smtpHost = configuration?["Sufficit:Identity:Smtp:Host"];
        if (!string.IsNullOrWhiteSpace(smtpHost))
        {
            services.AddTransient<IEmailSender, SmtpEmailSender>();
        }
        else
        {
            services.AddTransient<IEmailSender, LoggingEmailSender>();
        }

        // Register MVC controllers from this assembly (ExternalLoginController, etc)
        var mvc = services.AddControllers();
        mvc.PartManager.ApplicationParts.Add(
            new Microsoft.AspNetCore.Mvc.ApplicationParts.AssemblyPart(
                typeof(ServiceCollectionExtensions).Assembly));

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

        app.MapStaticAssets();
        app.MapRazorComponents<Components.App>()
           .AddInteractiveServerRenderMode();

        return app;
    }
}
