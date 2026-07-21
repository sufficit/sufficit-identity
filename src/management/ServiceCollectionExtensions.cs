using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Sufficit.Identity.Management;

/// <summary>
/// DI extensions for the optional management REST API.
/// Use <see cref="AddSufficitIdentityManagement"/> to register the management
/// controllers, then <see cref="UseSufficitIdentityManagementEndpoints"/> in the
/// pipeline to map their routes. Both are opt-in.
///
/// Configuration section: <c>Sufficit:Identity:Management</c>
///   - Enabled: bool (default false) — informational only; the host decides
///     whether to call this method. Provided for documentation/discovery.
///   - RoutePrefix: string (default "api")
///   - RequireAuthorization: bool (default true)
///   - RequiredScope: string (default "skoruba_identity_admin_api")
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the management API controllers and (optionally) the authorization
    /// policy that gates them. The host must also call
    /// <see cref="UseSufficitIdentityManagementEndpoints"/> in its pipeline.
    /// </summary>
    public static IServiceCollection AddSufficitIdentityManagement(
        this IServiceCollection services,
        IConfiguration configuration,
        string configurationSection = "Sufficit:Identity:Management")
    {
        var options = configuration
            .GetSection(configurationSection)
            .Get<ManagementOptions>() ?? new ManagementOptions();

        // Register the controllers in this assembly.
        services.AddControllers()
            .PartManager.ApplicationParts.Add(new AssemblyPart(Assembly.GetExecutingAssembly()));

        // Authorization policy for the management endpoints.
        if (options.RequireAuthorization)
        {
            services.AddAuthorization(builder =>
            {
                builder.AddPolicy("sufficit-identity-management", policy =>
                {
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(new ScopeRequirement(options.RequiredScope));
                });
            });

            services.AddSingleton<IAuthorizationHandler, ScopeHandler>();
        }

        return services;
    }
}

/// <summary>Policy requirement that checks for a specific OAuth scope.</summary>
public sealed class ScopeRequirement : IAuthorizationRequirement
{
    public string Scope { get; }
    public ScopeRequirement(string scope) => Scope = scope;
}

/// <summary>Validates that the access token carries the required scope.</summary>
public sealed class ScopeHandler : AuthorizationHandler<ScopeRequirement>
{
    private const string ScopeClaimType = "scope";

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context, ScopeRequirement requirement)
    {
        var scopes = context.User.FindAll(ScopeClaimType).SelectMany(c =>
            c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries));

        if (scopes.Contains(requirement.Scope))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

/// <summary>Bindable options for the management API.</summary>
public sealed class ManagementOptions
{
    public bool Enabled { get; init; } = false;
    public string RoutePrefix { get; init; } = "api";
    public bool RequireAuthorization { get; init; } = true;
    public string RequiredScope { get; init; } = "skoruba_identity_admin_api";
}

/// <summary>Endpoint mapping helper (call from Program.cs after Build).</summary>
public static class ManagementEndpointsExtensions
{
    public static IApplicationBuilder UseSufficitIdentityManagementEndpoints(
        this IApplicationBuilder app, IConfiguration configuration,
        string configurationSection = "Sufficit:Identity:Management")
    {
        var options = configuration
            .GetSection(configurationSection)
            .Get<ManagementOptions>() ?? new ManagementOptions();

        var prefix = options.RoutePrefix.Trim('/');

        app.MapWhen(ctx => ctx.Request.Path.StartsWithSegments($"/{prefix}"),
            branch => branch.UseRouting().UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            }));

        return app;
    }
}
