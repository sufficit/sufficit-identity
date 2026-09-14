using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;
using OpenIddict.Validation.AspNetCore;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;

namespace Sufficit.Identity.STS.Features;

/// <summary>
/// ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant): the IdP role is a
/// token exchange for a custom requested_token_type, and the resource
/// authorization server role is the RFC 7523 jwt-bearer grant. The grant logic
/// lives in Grants/IdentityAssertionGrants.cs.
/// </summary>
internal sealed class IdentityAssertionProtocolFeature : IProtocolFeature
{
    public string Name => "identity-assertions";

    public bool IsEnabled(SufficitIdentityOptions options) =>
        options.IdentityAssertions.Issuance.Enabled
        || options.IdentityAssertions.Redemption.Enabled;

    public void ConfigureServices(IServiceCollection services, ProtocolFeatureContext context)
    {
        // Always registered: the token exchange handler depends on the issuer,
        // and both handlers refuse the grant while their role is disabled.
        services.AddSingleton(new Grants.IdentityAssertionSigner(context.AuxiliarySigningCredentials));
        services.AddScoped<Grants.IdentityAssertionIssuer>();
        services.AddSingleton<Grants.IIdentityAssertionKeyResolver,
            Grants.DiscoveryIdentityAssertionKeyResolver>();
        services.AddScoped<Grants.ITokenGrantHandler, Grants.IdentityAssertionGrantHandler>();
    }

    public void ConfigureServer(OpenIddictServerBuilder server, ProtocolFeatureContext context)
    {
        var assertions = context.Options.IdentityAssertions;
        if (assertions.Issuance.Enabled)
        {
            server.Configure(serverOptions => serverOptions.RequestedTokenTypes.Add(
                Grants.IdentityAssertionGrant.TokenType));
            server.AddEventHandler(
                Grants.DeferIdentityAssertionRequestValidation.Descriptor);

            // OpenIddict rejects unregistered audience values before the grant
            // handler runs, and still requires the per-client "aud:" permission,
            // so each client must be allowed to address each trusted audience.
            var audiences = assertions.Issuance.Audiences
                .SelectMany(audience => audience.Aliases.Prepend(audience.Issuer))
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            if (audiences.Length > 0)
            {
                server.RegisterAudiences(audiences);
            }
        }

        if (assertions.Redemption.Enabled)
        {
            server.AllowCustomFlow(Grants.IdentityAssertionGrant.JwtBearerGrantType);
        }
    }

    public void ConfigureDiscovery(
        OpenIddictServerEvents.HandleConfigurationRequestContext discovery,
        ProtocolFeatureContext context)
    {
        // Draft §7: published only for the roles that are enabled.
        if (context.Options.IdentityAssertions.Issuance.Enabled)
        {
            discovery.Metadata["identity_chaining_requested_token_types_supported"] =
                new JsonArray(JsonValue.Create(Grants.IdentityAssertionGrant.TokenType));
        }

        if (context.Options.IdentityAssertions.Redemption.Enabled)
        {
            discovery.Metadata["authorization_grant_profiles_supported"] =
                new JsonArray(JsonValue.Create(Grants.IdentityAssertionGrant.GrantProfile));
        }
    }
}
