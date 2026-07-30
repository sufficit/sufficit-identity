using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Validation.AspNetCore;

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
        services.AddControllers()
            .PartManager.ApplicationParts.Add(
                new AssemblyPart(Assembly.GetExecutingAssembly()));
        services.TryAddScoped<IScimProvisioningService,
            ScimProvisioningService>();
        services.TryAddScoped<ScimExceptionFilter>();

        services.AddAuthorization(builder =>
        {
            builder.AddPolicy(PolicyName, policy =>
            {
                if (!options.RequireAuthorization)
                {
                    policy.RequireAssertion(_ => true);
                    return;
                }

                policy.AuthenticationSchemes.Add(
                    OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
                policy.RequireAuthenticatedUser();
                policy.Requirements.Add(
                    new ScimScopeRequirement(options.RequiredScope));
            });
        });
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IAuthorizationHandler,
                ScimScopeHandler>());

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
