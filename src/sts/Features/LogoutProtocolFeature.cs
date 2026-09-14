using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;

namespace Sufficit.Identity.STS.Features;

/// <summary>
/// OpenID Connect Back-Channel Logout 1.0 and Front-Channel Logout 1.0 fan-out
/// to relying parties on sign-out.
/// </summary>
internal sealed class LogoutProtocolFeature : IProtocolFeature
{
    public string Name => "logout";

    public bool IsEnabled(SufficitIdentityOptions options) =>
        options.BackchannelLogout.Enabled || options.FrontchannelLogout.Enabled;

    public void ConfigureServices(IServiceCollection services, ProtocolFeatureContext context)
    {
        var options = context.Options;

        // OpenIddict only consumes logout_tokens; the STS generates and
        // distributes them. The dispatcher is always registered because
        // AuthorizationController depends on it; while the feature is disabled
        // a no-op dispatcher skips the relying-party fan-out.
        if (options.BackchannelLogout.Enabled)
        {
            var issuer = string.IsNullOrWhiteSpace(options.Issuer)
                ? "https://localhost/"
                : options.Issuer;

            services.AddSingleton(new Logout.LogoutTokenGenerator(
                context.AuxiliarySigningCredentials, issuer));
            services.AddHttpClient<Logout.IBackchannelLogoutDispatcher, Logout.BackchannelLogoutDistributor>()
                .ConfigureHttpClient(client => client.Timeout = TimeSpan.FromSeconds(7))
                .UseSafeOutboundHttp(options.OutboundHttp);
        }
        else
        {
            services.AddSingleton<Logout.IBackchannelLogoutDispatcher, Logout.NullBackchannelLogoutDispatcher>();
        }

        // Relying-party URI lists are resolved from application metadata before
        // local sign-out and kept behind an opaque, one-time, two-minute key
        // while OpenIddict completes the end-session response.
        if (options.FrontchannelLogout.Enabled)
        {
            services.AddScoped<Logout.IFrontchannelLogoutDispatcher,
                Logout.FrontchannelLogoutDispatcher>();
        }
        else
        {
            services.AddSingleton<Logout.IFrontchannelLogoutDispatcher,
                Logout.NullFrontchannelLogoutDispatcher>();
        }
    }

    public void ConfigureDiscovery(
        OpenIddictServerEvents.HandleConfigurationRequestContext discovery,
        ProtocolFeatureContext context)
    {
        // Published as false while disabled, so clients skip the flow natively
        // instead of probing. The application cookie and ID tokens carry the
        // same sid, so session support follows each dispatcher flag.
        var options = context.Options;
        discovery.Metadata["backchannel_logout_supported"] =
            JsonValue.Create(options.BackchannelLogout.Enabled);
        discovery.Metadata["backchannel_logout_session_supported"] =
            JsonValue.Create(options.BackchannelLogout.Enabled);
        discovery.Metadata["frontchannel_logout_supported"] =
            JsonValue.Create(options.FrontchannelLogout.Enabled);
        discovery.Metadata["frontchannel_logout_session_supported"] =
            JsonValue.Create(options.FrontchannelLogout.Enabled);
    }
}
