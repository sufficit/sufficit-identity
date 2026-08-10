using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using OpenIddict.Validation.AspNetCore;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Scim;

public static class ScimServiceCollectionExtensions
{
    public const string PolicyName = "sufficit-identity-scim";

    public static IServiceCollection AddSufficitIdentityScim(
        this IServiceCollection services,
        IConfiguration configuration,
        string configurationSection = "Sufficit:Identity:Scim")
    {
        var section = configuration.GetSection(configurationSection);
        var options = section.Get<ScimOptions>() ?? new ScimOptions();
        services.AddOptions<ScimOptions>().Bind(section);
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IProductionPostureContributor,
                ScimProductionPostureContributor>());
        services.AddControllers()
            .PartManager.ApplicationParts.Add(
                new AssemblyPart(Assembly.GetExecutingAssembly()));
        services.TryAddScoped<IScimProvisioningService,
            ScimProvisioningService>();
        services.TryAddSingleton<IScimPublicOriginResolver,
            ScimPublicOriginResolver>();
        services.TryAddScoped<ScimExceptionFilter>();
        services.AddSingleton<IAuthorizationMiddlewareResultHandler,
            ScimAuthorizationAuditHandler>();

        services.AddAuthorization(builder =>
        {
            builder.AddPolicy(PolicyName, policy =>
            {
                policy.AuthenticationSchemes.Add(
                    OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
                policy.RequireAuthenticatedUser();
                // Scope compatibility and machine-client authorization are
                // independent boundaries. The obsolete RequireAuthorization
                // alias can relax only the scope check during migration.
                if (options.EffectiveRequireScope)
                {
                    policy.Requirements.Add(
                        new ScimScopeRequirement(options.RequiredScope));
                }
                if (options.RequireAllowedClient)
                {
                    policy.Requirements.Add(
                        new ScimClientRequirement(
                            options.AllowedClientIds,
                            options.ClientPolicyMode));
                }
                // M2 fix (eval M2): opt-in MFA for the full SCIM surface. SCIM
                // can reset any user's password and delete any account, so when
                // it is exposed to delegated (human) flows, the second factor is
                // required exactly as on the management API. Off by default
                // because M2M provisioning (client_credentials) cannot do MFA.
                if (options.RequireMfa)
                {
                    policy.Requirements.Add(new ScimMfaRequirement());
                }
            });
        });
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IAuthorizationHandler,
                ScimScopeHandler>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IAuthorizationHandler,
                ScimClientHandler>());
        if (options.RequireMfa)
        {
            services.TryAddEnumerable(
                ServiceDescriptor.Singleton<
                    IAuthorizationHandler,
                    ScimMfaHandler>());
        }

        return services;
    }
}

public sealed record ScimScopeRequirement(string Scope)
    : IAuthorizationRequirement;

public sealed class ScimScopeHandler
    : AuthorizationHandler<ScimScopeRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ScimScopeRequirement requirement)
    {
        var scopes = context.User.FindAll("scope")
            .SelectMany(claim => claim.Value.Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries));
        if (scopes.Contains(requirement.Scope, StringComparer.Ordinal))
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}

/// <summary>
/// Policy requirement that the SCIM access token carries evidence of
/// multi-factor authentication (RFC 8176 <c>amr</c> claim). Mirrors the
/// management API's <c>MfaRequirement</c>. Added to the SCIM policy only when
/// <see cref="ScimOptions.RequireMfa"/> is true.
/// </summary>
public sealed class ScimMfaRequirement : IAuthorizationRequirement;

/// <summary>
/// Validates the <see cref="ScimMfaRequirement"/>: the principal must carry an
/// <c>amr</c> claim with at least one MFA-indicating value (RFC 8176). Succeeds
/// only then; otherwise leaves the requirement unsatisfied (the policy denies).
/// </summary>
public sealed class ScimMfaHandler : AuthorizationHandler<ScimMfaRequirement>
{
    private const string AmrClaimType = "amr";

    // amr values per RFC 8176 that prove a second factor was used.
    private static readonly HashSet<string> MfaValues = new(StringComparer.Ordinal)
    {
        "mfa", "otp", "hwk", "sms", "vcm", "fpt", "eye", "voice", "retina"
    };

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ScimMfaRequirement requirement)
    {
        var amrValues = context.User.FindAll(AmrClaimType).Select(c => c.Value);
        if (amrValues.Any(v => MfaValues.Contains(v)))
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}

/// <summary>
/// Policy requirement restricting SCIM to an explicit allow-list of OAuth
/// client_id values (M4, eval). SCIM operates with full-directory-trust, so
/// only deliberately-listed provisioning clients may call it.
/// <see cref="AllowedClientIds"/> empty (the default) fails closed.
/// </summary>
public sealed record ScimClientRequirement(
    string[] AllowedClientIds,
    ScimClientPolicyMode Mode = ScimClientPolicyMode.Enforce)
    : IAuthorizationRequirement;

/// <summary>
/// Validates <see cref="ScimClientRequirement"/>: the principal's
/// <c>client_id</c>/<c>azp</c> claim must appear in the allow-list. Succeeds
/// only then; when the allow-list is empty, the requirement is never satisfied
/// (SCIM stays inaccessible until an operator lists a trusted client).
/// </summary>
public sealed class ScimClientHandler(
    Microsoft.Extensions.Logging.ILogger<ScimClientHandler> logger)
    : AuthorizationHandler<ScimClientRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ScimClientRequirement requirement)
    {
        var clientId = context.User.FindFirst("client_id")?.Value
            ?? context.User.FindFirst("azp")?.Value;
        var allowed = clientId is not null
            && requirement.AllowedClientIds.Contains(
                clientId, StringComparer.Ordinal);
        if (allowed)
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        logger.LogWarning(
            "SCIM client policy {PolicyMode} rejected client {ClientId}; configured allow-list count is {AllowedClientCount}",
            requirement.Mode,
            clientId ?? "<missing>",
            requirement.AllowedClientIds.Length);
        if (requirement.Mode is ScimClientPolicyMode.Observe)
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}
