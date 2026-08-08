using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using Sufficit.Identity.Application.Branding;
using Sufficit.Identity.Core.Branding;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorizations;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Branding;
using Sufficit.Identity.Management.Claims;
using Sufficit.Identity.Management.Clients;
using Sufficit.Identity.Management.Controllers;
using Sufficit.Identity.Management.Database;
using Sufficit.Identity.Management.Overview;
using Sufficit.Identity.Management.Metrics;
using Sufficit.Identity.Core.Metrics;
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
///   - RequiredScope: string (default "identity.management")
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
        var routePrefix = NormalizeRoutePrefix(options.RoutePrefix);
        services.AddControllers(mvc =>
            {
                mvc.Filters.Add<ManagementExceptionFilter>();
                mvc.Conventions.Add(
                    new ManagementRoutePrefixConvention(routePrefix));
            })
            .PartManager.ApplicationParts.Add(new AssemblyPart(Assembly.GetExecutingAssembly()));

        services.TryAddScoped<OpenIddictManifestProvisioner>();
        services.TryAddScoped<IProvisioningManagementService,
            ProvisioningManagementService>();
        services.TryAddScoped<IManagementEntitlementResolver,
            ScopeAndRoleManagementEntitlementResolver>();
        services.TryAddScoped<IManagementAccessPolicyProvider,
            ConfigurationManagementAccessPolicyProvider>();
        // H3 (eval): object-level authorization boundary. Permissive default
        // preserves the trust-everything posture; a deployment replaces it via
        // services.Replace<IManagementObjectAccessPolicy, ...>() to enforce
        // tenant/object scoping (mirrors how the host replaces the resolver).
        services.TryAddScoped<IManagementObjectAccessPolicy,
            DefaultManagementObjectAccessPolicy>();
        services.TryAddScoped<IManagementAuthorizationEvaluator,
            CapabilityManagementAuthorizationEvaluator>();
        services.TryAddScoped<IManagementAuditService, ManagementAuditService>();
        services.TryAddScoped<IClientManagementService, ClientManagementService>();
        services.TryAddScoped<IClientConfigurationDraftService,
            ClientConfigurationDraftService>();
        services.TryAddSingleton(TimeProvider.System);
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
        services.TryAddScoped<IDatabaseMonitoringService,
            DatabaseMonitoringService>();
        services.TryAddScoped<IMetricsManagementService,
            MetricsManagementService>();
        services.TryAddSingleton<IdentityMetricsRuntimeState>();
        services.TryAddSingleton<IBrandingThemeProvider,
            BrandingThemeProvider>();
        services.TryAddSingleton<IUserAvatarUrlResolver,
            UserAvatarUrlResolver>();
        services.TryAddSingleton<IClientSecretResolver, MissingClientSecretResolver>();

        // The named policy is always registered because controllers reference
        // it unconditionally. RequireAuthorization=false remains an explicit
        // compatibility mode instead of producing an unresolvable-policy 500.
        services.AddAuthorization(builder =>
        {
            builder.AddPolicy("sufficit-identity-management", policy =>
            {
                if (options.RequireAuthorization)
                {
                    policy.AuthenticationSchemes.Add(
                        OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(new ScopeRequirement(options.RequiredScope));
                    if (options.RequireMfa)
                    {
                        policy.Requirements.Add(new MfaRequirement());
                    }

                }
                else
                {
                    policy.RequireAssertion(_ => true);
                }
            });
        });

        if (options.RequireAuthorization)
        {
            services.AddSingleton<IAuthorizationHandler, ScopeHandler>();
            // MfaHandler evaluates the MfaRequirement added to the policy when
            // RequireMfa is true. Without this registration the requirement is
            // never satisfied, causing fail-closed (every management request
            // denied) when RequireMfa is on.
            services.AddSingleton<IAuthorizationHandler, MfaHandler>();
        }

        return services;
    }

    private static string NormalizeRoutePrefix(string? value)
    {
        var prefix = (value ?? "api").Trim('/');
        if (prefix.Length == 0
            || prefix.Contains('{', StringComparison.Ordinal)
            || prefix.Contains('}', StringComparison.Ordinal)
            || prefix.Contains('?', StringComparison.Ordinal)
            || prefix.Contains('#', StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Management RoutePrefix must be a non-empty literal path.");
        }

        return prefix;
    }
}

public sealed class ManagementRoutePrefixConvention(string routePrefix)
    : IApplicationModelConvention
{
    public void Apply(ApplicationModel application)
    {
        foreach (var controller in application.Controllers.Where(controller =>
                     controller.ControllerType.Assembly == typeof(ManagementRoutePrefixConvention).Assembly))
        {
            foreach (var selector in controller.Selectors)
            {
                var route = selector.AttributeRouteModel;
                if (route?.Template is not { } template)
                {
                    continue;
                }

                if (string.Equals(template, "api", StringComparison.OrdinalIgnoreCase))
                {
                    route.Template = routePrefix;
                }
                else if (template.StartsWith("api/", StringComparison.OrdinalIgnoreCase))
                {
                    route.Template = routePrefix + template[3..];
                }
            }
        }
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
        // OpenIddict keeps granted scopes in private principal metadata while
        // processing reference tokens. Other JWT middleware can expose the
        // same information as the public RFC `scope` claim. Accept both
        // representations so a valid management token is not denied merely
        // because of the validation transport used by the host.
        var hasPublicScope = context.User
            .FindAll(ScopeClaimType)
            .SelectMany(claim => claim.Value.Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries))
            .Contains(requirement.Scope, StringComparer.Ordinal);

        if (context.User.HasScope(requirement.Scope) || hasPublicScope)
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
