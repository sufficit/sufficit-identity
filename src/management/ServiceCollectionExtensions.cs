using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using Sufficit.Identity.Application.Branding;
using Sufficit.Identity.Application.Security;
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
using Sufficit.Identity.Management.Mcp;
using Sufficit.Identity.Management.OperatorTokens;
using Sufficit.Identity.Core.Metrics;
using Sufficit.Identity.Management.Provisioning;
using Sufficit.Identity.Management.Scopes;
using Sufficit.Identity.Management.Sessions;
using Sufficit.Identity.Management.Users;
using Sufficit.Identity.Management.Vault;

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

        // F-4 (eval 2026-08-14): RequireAuthorization=false turns the entire
        // management surface — directory, clients, vault metadata, provisioning
        // — into an anonymous API. Outside Development this is now rejected at
        // composition time instead of remaining a working switch that only the
        // production posture check would report after startup. The posture
        // finding (management-authorization-disabled) stays registered as a
        // second layer for hosts that compose the policy by other means.
        // The environment prefers the configuration value (tests inject it)
        // and falls back to the raw variable because this DI extension has no
        // IHostEnvironment — the same pattern the vault extension uses.
        ValidateManagementAuthorizationMode(
            options,
            configuration["ASPNETCORE_ENVIRONMENT"]
                ?? Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"));

        services.AddOptions<ManagementOptions>()
            .Bind(configurationRoot);
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IProductionPostureContributor,
                ManagementProductionPostureContributor>());
        services.Replace(ServiceDescriptor.Singleton<IReservedScopePolicy>(
            new ReservedScopePolicy(options.ReservedApiScopes
                .Concat(RetiredIdentityScopes.Names))));
        services.TryAddSingleton<IClientScopeGrantPolicy,
            ClientScopeGrantPolicy>();
        services.TryAddSingleton<IClientDefinitionValidator,
            ClientDefinitionValidator>();
        services.TryAddSingleton<IIdentityRuntimeCapabilityCatalog,
            DisabledIdentityRuntimeCapabilityCatalog>();

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
        services.TryAddScoped<IProvisioningTokenManagementService,
            ProvisioningTokenManagementService>();
        services.TryAddScoped<IProvisioningTokenIssuer,
            ProvisioningTokenIssuer>();
        services.TryAddScoped<IOperatorTokenManagementService,
            OperatorTokenManagementService>();
        services.TryAddScoped<IManagementEntitlementResolver,
            ScopeAndRoleManagementEntitlementResolver>();
        services.TryAddScoped<IManagementAccessPolicyProvider,
            ConfigurationManagementAccessPolicyProvider>();
        services.TryAddScoped<IProtectedPrincipalAccessPolicy,
            ConfigurationProtectedPrincipalAccessPolicy>();
        services.TryAddScoped<IManagementObjectAccessPolicy,
            ConfigurationManagementObjectAccessPolicy>();
        services.TryAddScoped<IManagementAuthorizationEvaluator,
            CapabilityManagementAuthorizationEvaluator>();
        services.TryAddSingleton<ManagementAuthorizationMiddlewareResultHandler>();
        // Replace, not TryAdd: AddSufficitIdentitySTS runs first and its
        // AddAuthorization already registered the framework handler, so a
        // TryAdd here would silently lose and neither the management problem
        // details nor the MCP discovery pointer would ever be emitted.
        services.Replace(
            ServiceDescriptor.Singleton<IAuthorizationMiddlewareResultHandler>(
                provider => provider.GetRequiredService<
                    ManagementAuthorizationMiddlewareResultHandler>()));
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
        services.TryAddScoped<IVaultSecretsManagementService,
            VaultSecretsManagementService>();
        services.TryAddSingleton<McpSessionManager>();
        services.TryAddScoped<VaultMcpTools>();
        services.TryAddScoped<SelfServiceMcpTools>();
        services.TryAddScoped<IdentityMcpToolRegistry>();
        services.TryAddSingleton<IdentityMetricsRuntimeState>();
        services.TryAddSingleton<IBrandingThemeProvider,
            BrandingThemeProvider>();
        services.TryAddSingleton<IUserAvatarUrlResolver,
            UserAvatarUrlResolver>();
        services.TryAddSingleton<IClientSecretResolver, MissingClientSecretResolver>();

        // The named policy is always registered because controllers reference
        // it unconditionally. The RequireAuthorization=false branch below is
        // reachable only in Development — the guard at the top of this method
        // rejects the setting everywhere else — and exists so a Development
        // host never faces an unresolvable-policy 500.
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
            builder.AddPolicy("sufficit-identity-mcp", policy =>
            {
                policy.AuthenticationSchemes.Add(
                    OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
                policy.RequireAuthenticatedUser();
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

    /// <summary>
    /// F-4 (eval 2026-08-14): anonymous management is a Development-only
    /// migration scenario. Kept as a pure function so the mode contract is
    /// unit-testable without mutating the process environment.
    /// </summary>
    internal static void ValidateManagementAuthorizationMode(
        ManagementOptions options,
        string? environment)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!options.RequireAuthorization
            && !string.Equals(environment, "Development", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Sufficit:Identity:Management:RequireAuthorization=false is only supported in " +
                "Development. Outside Development it would expose the full management API " +
                "(users, clients, scopes, sessions, vault metadata, provisioning) without " +
                "authentication. Remove the setting, or run a dedicated Development " +
                "environment for the anonymous migration scenario.");
        }
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
public sealed class MfaHandler(
    IOptions<ManagementOptions>? options = null)
    : AuthorizationHandler<MfaRequirement>
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
        if (options?.Value.Authorization.IsConfiguredServiceClient(
                context.User) is true)
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

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
