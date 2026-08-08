using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.UI.Abstractions.Hosting;
using Sufficit.Identity.UI.Vault.Data;

namespace Sufficit.Identity.UI.Vault;

public static class VaultUiPolicies
{
    public const string User = "sufficit-identity-vault-user";
    public const string Admin = "sufficit-identity-vault-admin";
}

public sealed class VaultAdminRequirement : IAuthorizationRequirement;

/// <summary>
/// Keeps the personal Vault UI composable when the optional management API is
/// disabled. The host replaces this deny-by-default resolver when management
/// is enabled, so the operator surface remains capability protected.
/// </summary>
internal sealed class DenyManagementEntitlementResolver : IManagementEntitlementResolver
{
    public ValueTask<ManagementEntitlements> ResolveAsync(
        System.Security.Claims.ClaimsPrincipal principal,
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(new ManagementEntitlements(
            new HashSet<string>(StringComparer.Ordinal)));
}

internal sealed class VaultAdminAuthorizationHandler(
    IManagementEntitlementResolver entitlements)
    : AuthorizationHandler<VaultAdminRequirement>
{
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        VaultAdminRequirement requirement)
    {
        var resolved = await entitlements.ResolveAsync(context.User);
        if (resolved.Contains(ManagementCapabilities.VaultSecretsRead))
            context.Succeed(requirement);
    }
}

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSufficitIdentityVaultUI(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var section = configuration.GetSection(VaultUiOptions.SectionName);
        services.AddOptions<VaultUiOptions>().Bind(section);
        services.TryAddSingleton<UiModuleRegistry>();
        services.TryAddSingleton<IUiModuleRegistry>(sp =>
            sp.GetRequiredService<UiModuleRegistry>());
        services.TryAddScoped<IManagementEntitlementResolver,
            DenyManagementEntitlementResolver>();
        services.AddSingleton(new UiModuleDescriptor(
            "sufficit-identity-vault-ui",
            UiSurface.Vault,
            new Version(0, 4, 0),
            new Version(0, 4, 0)));
        services.AddAuthorization(options =>
        {
            options.AddPolicy(VaultUiPolicies.User, policy =>
                policy.RequireAuthenticatedUser());
            options.AddPolicy(VaultUiPolicies.Admin, policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.AddRequirements(new VaultAdminRequirement());
            });
        });
        services.AddScoped<IAuthorizationHandler, VaultAdminAuthorizationHandler>();
        services.AddCascadingAuthenticationState();
        services.TryAddScoped<VaultDataSource>();
        services.AddRazorComponents().AddInteractiveServerComponents();
        return services;
    }

    public static IApplicationBuilder UseSufficitIdentityVaultUI(
        this WebApplication app)
    {
        MapEmbeddedAsset(app, "/_content/Sufficit.Identity.UI.Vault/vault.css",
            "Sufficit.Identity.UI.Vault.Assets.vault.css",
            "text/css; charset=utf-8");

        app.MapRazorComponents<Components.App>()
            .AddInteractiveServerRenderMode();
        return app;
    }

    private static void MapEmbeddedAsset(
        WebApplication app, string path, string resource, string contentType)
    {
        app.MapGet(path, (IWebHostEnvironment environment) =>
        {
            var assembly = typeof(ServiceCollectionExtensions).Assembly;
            var stream = assembly.GetManifestResourceStream(resource);
            return stream is null
                ? Results.NotFound()
                : Results.Stream(stream, contentType);
        }).AllowAnonymous();
    }
}
