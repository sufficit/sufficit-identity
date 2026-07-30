using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sufficit.Identity.Core.Branding;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorizations;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Branding;
using Sufficit.Identity.Management.Claims;
using Sufficit.Identity.Management.Clients;
using Sufficit.Identity.Management.Controllers;
using Sufficit.Identity.Management.Overview;
using Sufficit.Identity.Management.Provisioning;
using Sufficit.Identity.Management.Scopes;
using Sufficit.Identity.Management.Sessions;
using Sufficit.Identity.Management.Users;

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
        var configurationRoot = configuration.GetSection(configurationSection);

        services.AddOptions<ManagementOptions>()
            .Bind(configurationRoot);

        // Register the controllers in this assembly.
        services.AddControllers(options =>
            {
                options.Filters.Add<ManagementExceptionFilter>();
            })
            .PartManager.ApplicationParts.Add(new AssemblyPart(Assembly.GetExecutingAssembly()));

        services.TryAddScoped<OpenIddictManifestProvisioner>();
        services.TryAddScoped<IManagementEntitlementResolver,
            ScopeAndRoleManagementEntitlementResolver>();
        services.TryAddScoped<IManagementAccessPolicyProvider,
            ConfigurationManagementAccessPolicyProvider>();
        services.TryAddScoped<IManagementAuthorizationEvaluator,
            CapabilityManagementAuthorizationEvaluator>();
        services.TryAddScoped<IManagementAuditService, ManagementAuditService>();
        services.TryAddScoped<IClientManagementService, ClientManagementService>();
        services.TryAddScoped<IClaimManagementService, ClaimManagementService>();
        services.TryAddScoped<IScopeManagementService, ScopeManagementService>();
        services.TryAddScoped<ISessionManagementService,
            SessionManagementService>();
        services.TryAddScoped<IAuthorizationManagementService,
            AuthorizationManagementService>();
        services.TryAddScoped<IBrandingManagementService,
            BrandingManagementService>();
        services.TryAddScoped<IUserManagementService, UserManagementService>();
        services.TryAddScoped<IManagementOverviewService,
            ManagementOverviewService>();
        services.TryAddScoped<IManagementUserSessionRevoker,
            OpenIddictManagementUserSessionRevoker>();
        services.TryAddSingleton<IBrandingThemeProvider,
            BrandingThemeProvider>();
        services.TryAddSingleton<IUserAvatarUrlResolver,
            UserAvatarUrlResolver>();
        services.TryAddSingleton<IClientSecretResolver, MissingClientSecretResolver>();

        // Authorization policy for the management endpoints.
        if (options.RequireAuthorization)
        {
            services.AddAuthorization(builder =>
            {
                builder.AddPolicy("sufficit-identity-management", policy =>
                {
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(new ScopeRequirement(options.RequiredScope));

                    // Capability and MFA decisions are applied by the shared
                    // application services, so embedded UI and HTTP adapters
                    // cannot diverge. This transport policy owns only bearer
                    // authentication and the Management API scope.
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

/// <summary>
/// Policy requirement that the access token carries evidence of multi-factor
/// authentication (RFC 8705 / OIDC Core <c>amr</c> claim — item 5.2 [L3]).
/// Accepts the standard <c>amr</c> values that indicate a second factor was
/// used: <c>mfa</c> (MFA performed), <c>otp</c> (one-time password), and
/// <c>hwk</c> (hardware key). A token minted from a password-only session has
/// none of these, so it is rejected when this requirement is active.
/// </summary>
public sealed class MfaRequirement : IAuthorizationRequirement;

/// <summary>
/// Validates the <see cref="MfaRequirement"/>: the principal must carry an
/// <c>amr</c> claim with at least one MFA-indicating value. Succeeds only then;
/// otherwise leaves the requirement unsatisfied (the policy then denies).
/// </summary>
public sealed class MfaHandler : AuthorizationHandler<MfaRequirement>
{
    private const string AmrClaimType = "amr";

    // amr values per RFC 8176 that prove a second factor was used.
    private static readonly HashSet<string> MfaValues = new(StringComparer.Ordinal)
    {
        "mfa", "otp", "hwk", "sms", "vcm", "fpt", "eye", "voice", "retina"
    };

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context, MfaRequirement requirement)
    {
        var amrValues = context.User.FindAll(AmrClaimType).Select(c => c.Value);
        if (amrValues.Any(v => MfaValues.Contains(v)))
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

    public ManagementAuthorizationOptions Authorization { get; init; } = new();

    /// <summary>
    /// When <c>true</c>, the management policy additionally requires an <c>amr</c>
    /// claim proving multi-factor authentication (item 5.2 [L3]). Default
    /// <c>false</c>: flip only after the login UI emits <c>amr</c> for
    /// MFA-completed sessions, otherwise every admin token is rejected.
    /// </summary>
    public bool RequireMfa { get; init; } = false;
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
