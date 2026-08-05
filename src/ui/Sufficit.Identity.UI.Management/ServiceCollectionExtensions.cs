using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.UI.Management.Audit;
using Sufficit.Identity.UI.Management.Authorizations;
using Sufficit.Identity.UI.Management.Branding;
using Sufficit.Identity.UI.Management.Claims;
using Sufficit.Identity.UI.Management.Clients;
using Sufficit.Identity.UI.Management.Configuration;
using Sufficit.Identity.UI.Management.Overview;
using Sufficit.Identity.UI.Management.Provisioning;
using Sufficit.Identity.UI.Management.Scopes;
using Sufficit.Identity.UI.Management.Sessions;
using Sufficit.Identity.UI.Management.Users;

namespace Sufficit.Identity.UI.Management;

public static class ManagementUiPolicies
{
    public const string Access = "sufficit-identity-management-ui-access";
    public const string ManageClients = "sufficit-identity-management-ui-clients";
    public const string ManageClaims = "sufficit-identity-management-ui-claims";
    public const string ManageScopes = "sufficit-identity-management-ui-scopes";
    public const string ManageSessions =
        "sufficit-identity-management-ui-sessions";
    public const string ManageAuthorizations =
        "sufficit-identity-management-ui-authorizations";
    public const string ManageBranding = "sufficit-identity-management-ui-branding";
    public const string ReadAudit = "sufficit-identity-management-ui-audit";
    public const string ManageProvisioning =
        "sufficit-identity-management-ui-provisioning";
}

public sealed class ManagementCapabilityRequirement(
    string capability,
    string resourceType)
    : IAuthorizationRequirement
{
    public string Capability { get; } = capability;

    public string ResourceType { get; } = resourceType;
}

public sealed class ManagementUiAccessRequirement : IAuthorizationRequirement;

internal sealed class ManagementUiAccessAuthorizationHandler(
    IManagementEntitlementResolver entitlements)
    : AuthorizationHandler<ManagementUiAccessRequirement>
{
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ManagementUiAccessRequirement requirement)
    {
        var resolved = await entitlements.ResolveAsync(context.User);
        if (resolved.Capabilities.Count is not 0)
        {
            context.Succeed(requirement);
        }
    }
}

internal sealed class ManagementCapabilityAuthorizationHandler(
    IManagementAuthorizationEvaluator evaluator)
    : AuthorizationHandler<ManagementCapabilityRequirement>
{
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ManagementCapabilityRequirement requirement)
    {
        var decision = await evaluator.EvaluateAsync(
            context.User,
            requirement.Capability,
            new ManagementResource(requirement.ResourceType));

        if (decision.IsAllowed)
        {
            context.Succeed(requirement);
        }
    }
}

/// <summary>
/// Registers and maps the management Razor Class Library in the same process
/// as the identity host. Authentication is supplied by the host's ASP.NET
/// Identity cookie; no self-referential OIDC/BFF client is created.
/// </summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSufficitIdentityManagementUI(
        this IServiceCollection services,
        IConfiguration configuration,
        string configurationSection = ManagementUiOptions.SectionName)
    {
        var configurationRoot = configuration.GetSection(configurationSection);
        var options = configurationRoot.Get<ManagementUiOptions>()
            ?? new ManagementUiOptions();

        // Resolve these eagerly so invalid/root PathBase values fail at startup,
        // before the host accepts traffic.
        _ = options.GetPathBase();
        services.AddOptions<ManagementUiOptions>()
            .Bind(configurationRoot);
        services.AddAuthorization(authorization =>
        {
            authorization.AddPolicy(ManagementUiPolicies.Access, policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.Requirements.Add(new ManagementUiAccessRequirement());
            });

            authorization.AddPolicy(ManagementUiPolicies.ManageClients, policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.Requirements.Add(
                    new ManagementCapabilityRequirement(
                        ManagementCapabilities.ClientsRead,
                        ManagementResourceTypes.ClientCollection));
            });

            authorization.AddPolicy(ManagementUiPolicies.ManageClaims, policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.Requirements.Add(
                    new ManagementCapabilityRequirement(
                        ManagementCapabilities.ClaimsRead,
                        ManagementResourceTypes.ClaimCollection));
            });

            authorization.AddPolicy(ManagementUiPolicies.ManageScopes, policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.Requirements.Add(
                    new ManagementCapabilityRequirement(
                        ManagementCapabilities.ScopesRead,
                        ManagementResourceTypes.ScopeCollection));
            });

            authorization.AddPolicy(
                ManagementUiPolicies.ManageSessions,
                policy =>
                {
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(
                        new ManagementCapabilityRequirement(
                            ManagementCapabilities.SessionsRead,
                            ManagementResourceTypes.SessionCollection));
                });

            authorization.AddPolicy(
                ManagementUiPolicies.ManageAuthorizations,
                policy =>
                {
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(
                        new ManagementCapabilityRequirement(
                            ManagementCapabilities.AuthorizationsRead,
                            ManagementResourceTypes.AuthorizationCollection));
                });

            authorization.AddPolicy(ManagementUiPolicies.ManageBranding, policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.Requirements.Add(
                    new ManagementCapabilityRequirement(
                        ManagementCapabilities.BrandingRead,
                        ManagementResourceTypes.BrandingCollection));
            });

            authorization.AddPolicy(ManagementUiPolicies.ReadAudit, policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.Requirements.Add(
                    new ManagementCapabilityRequirement(
                        ManagementCapabilities.AuditRead,
                        ManagementResourceTypes.Audit));
            });

            authorization.AddPolicy(
                ManagementUiPolicies.ManageProvisioning,
                policy =>
                {
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(
                        new ManagementCapabilityRequirement(
                            ManagementCapabilities.ProvisioningPreview,
                            ManagementResourceTypes.Provisioning));
                });
        });

        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IAuthorizationHandler,
                ManagementCapabilityAuthorizationHandler>());
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IAuthorizationHandler,
                ManagementUiAccessAuthorizationHandler>());
        services.TryAddScoped<ManagementClientDataSource>();
        services.TryAddScoped<ManagementClaimDataSource>();
        services.TryAddScoped<ManagementScopeDataSource>();
        services.TryAddScoped<ManagementSessionDataSource>();
        services.TryAddScoped<ManagementAuthorizationDataSource>();
        services.TryAddScoped<ManagementBrandingDataSource>();
        services.TryAddScoped<ManagementAuditDataSource>();
        services.TryAddScoped<ManagementUserDataSource>();
        services.TryAddScoped<ManagementOverviewDataSource>();
        services.TryAddScoped<ManagementProvisioningDataSource>();

        services.AddCascadingAuthenticationState();
        services.AddRazorComponents()
            .AddInteractiveServerComponents();
        services.AddAntiforgery();

        return services;
    }

    /// <summary>
    /// Maps the management UI under its configured non-root path. Call after
    /// UseAuthentication/UseAuthorization and before mapping the public UI.
    /// </summary>
    public static IApplicationBuilder UseSufficitIdentityManagementUI(
        this WebApplication app)
    {
        var options = app.Services
            .GetRequiredService<IOptions<ManagementUiOptions>>()
            .Value;
        var pathBase = options.GetPathBase();

        MapEmbeddedAsset(
            app,
            "/_content/Sufficit.Identity.UI.Management/img/logo-mark.png",
            "Sufficit.Identity.UI.Management.Assets.logo-mark.png",
            "image/png");
        MapEmbeddedAsset(
            app,
            "/_content/Sufficit.Identity.UI.Management/fonts/inter-latin.woff2",
            "Sufficit.Identity.UI.Management.Assets.inter-latin.woff2",
            "font/woff2");
        MapEmbeddedAsset(
            app,
            "/_content/Sufficit.Identity.UI.Management/fonts/inter-latin-500.woff2",
            "Sufficit.Identity.UI.Management.Assets.inter-latin-500.woff2",
            "font/woff2");
        MapEmbeddedAsset(
            app,
            "/_content/Sufficit.Identity.UI.Management/fonts/inter-latin-600.woff2",
            "Sufficit.Identity.UI.Management.Assets.inter-latin-600.woff2",
            "font/woff2");
        MapEmbeddedAsset(
            app,
            "/_content/Sufficit.Identity.UI.Management/_framework/blazor.web.js",
            "Sufficit.Identity.UI.Management.Assets.blazor.web.js",
            "text/javascript; charset=utf-8");
        MapEmbeddedAsset(
            app,
            "/_content/Sufficit.Identity.UI.Management/app.css",
            "Sufficit.Identity.UI.Management.Assets.app.css",
            "text/css; charset=utf-8");
        MapEmbeddedAsset(
            app,
            "/_content/Sufficit.Identity.UI.Management/users.css",
            "Sufficit.Identity.UI.Management.Assets.users.css",
            "text/css; charset=utf-8");

        // A route-group prefix becomes part of the SSR RouteData template,
        // while the component Router knows the pages as "/" and "/clients".
        // A PathBase branch removes "/management" before endpoint matching, so
        // both SSR and interactive navigation see the same relative templates.
        app.Map(pathBase, management =>
        {
            management.UseRouting();
            management.UseAuthentication();
            management.UseAuthorization();
            management.UseAntiforgery();
            management.UseEndpoints(endpoints =>
            {
                // CookieAuthenticationHandler includes Request.PathBase in its
                // LoginPath/AccessDeniedPath redirects. Forward those branch
                // aliases to the real account pages owned by the host.
                endpoints.MapGet("/account/login", (HttpContext context) =>
                    Results.Redirect(
                        $"/account/login{context.Request.QueryString}"))
                    .AllowAnonymous();
                endpoints.MapGet("/account/accessdenied", (HttpContext context) =>
                    Results.Redirect(
                        $"/account/accessdenied{context.Request.QueryString}"))
                    .AllowAnonymous();

                endpoints.MapRazorComponents<Components.App>()
                    .AddInteractiveServerRenderMode()
                    .RequireAuthorization(ManagementUiPolicies.Access);
            });
        });

        return app;
    }

    private static void MapEmbeddedAsset(
        WebApplication app,
        string route,
        string resourceName,
        string contentType)
    {
        app.MapGet(route, () =>
        {
            var stream = typeof(Components.App).Assembly
                .GetManifestResourceStream(resourceName);
            return stream is null
                ? Results.NotFound()
                : Results.Stream(stream, contentType);
        }).AllowAnonymous();
    }
}
