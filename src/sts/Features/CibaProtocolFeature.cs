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
/// OpenID Connect CIBA Core 1.0, poll mode: initiation and approval in
/// <c>CibaController</c>, polling at the token endpoint through
/// <c>Grants.CibaGrantHandler</c>.
/// </summary>
internal sealed class CibaProtocolFeature : IProtocolFeature
{
    public string Name => "ciba";

    public bool IsEnabled(SufficitIdentityOptions options) => options.Ciba.Enabled;

    public IEnumerable<string> RuntimeCapabilities(SufficitIdentityOptions options) =>
        options.Ciba.Enabled ? [ManagementRuntimeCapabilities.Ciba] : [];

    public void ConfigureServices(IServiceCollection services, ProtocolFeatureContext context)
    {
        // The pending-request store has a database primary with the distributed
        // cache alongside, so CIBA works across replicas and survives restarts.
        // Everything is registered regardless of the option so the disabled
        // controller can answer 404 instead of failing activation; the grant
        // handler refuses the grant while CIBA is disabled.
        services.AddSingleton(sp => new Ciba.DistributedCibaPendingRequestStore(
            sp.GetRequiredService<Microsoft.Extensions.Caching.Distributed.IDistributedCache>(),
            TimeProvider.System,
            sp.GetRequiredService<Sufficit.Identity.Vault.IKeyVault>()));
        services.AddSingleton(sp => new Ciba.DatabaseCibaPendingRequestStore(
            sp.GetRequiredService<IDbContextFactory<AppDbContext>>(),
            TimeProvider.System));
        services.AddSingleton<Ciba.ICibaPendingRequestStore,
            Ciba.RollingCibaPendingRequestStore>();
        services.AddScoped<Ciba.ICibaClientPolicy, Ciba.CibaClientPolicy>();
        services.AddScoped<Ciba.ICibaClientAuthenticator, Ciba.CibaClientAuthenticator>();
        services.AddScoped<Grants.ITokenGrantHandler, Grants.CibaGrantHandler>();
    }

    public void ConfigureServer(OpenIddictServerBuilder server, ProtocolFeatureContext context)
    {
        // Poll mode (§10.1) at the standard token endpoint, so the grant
        // inherits client authentication, DPoP and mTLS binding.
        if (context.Options.Ciba.Enabled)
        {
            server.AllowCustomFlow(Grants.CibaGrantHandler.GrantType);
        }
    }

    public void ConfigureDiscovery(
        OpenIddictServerEvents.HandleConfigurationRequestContext discovery,
        ProtocolFeatureContext context)
    {
        // §4: OpenIddict lists the grant type in grant_types_supported from the
        // custom flow; the initiation endpoint and delivery mode are ours.
        if (!context.Options.Ciba.Enabled)
        {
            return;
        }

        discovery.Metadata["backchannel_authentication_endpoint"] =
            JsonValue.Create(new Uri(
                discovery.Issuer ?? new Uri("/", UriKind.Relative),
                "bc-authorize").AbsoluteUri);
        discovery.Metadata["backchannel_token_delivery_modes_supported"] =
            new JsonArray(JsonValue.Create("poll"));
        discovery.Metadata["backchannel_user_code_parameter_supported"] =
            JsonValue.Create(false);
    }
}
