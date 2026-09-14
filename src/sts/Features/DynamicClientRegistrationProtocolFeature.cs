using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;

namespace Sufficit.Identity.STS.Features;

/// <summary>
/// OAuth 2.0 Dynamic Client Registration (RFC 7591) at
/// <c>/connect/register</c>; the endpoint itself is
/// <c>Controllers.RegistrationController</c>.
/// </summary>
internal sealed class DynamicClientRegistrationProtocolFeature : IProtocolFeature
{
    public string Name => "dynamic-client-registration";

    public bool IsEnabled(SufficitIdentityOptions options) => options.Mcp.Dcr.Enabled;

    // Initial access tokens are issued at runtime through the management API,
    // so an enabled endpoint is usable without startup configuration.
    public IEnumerable<string> RuntimeCapabilities(SufficitIdentityOptions options) =>
        options.Mcp.Dcr.Enabled ? [ManagementRuntimeCapabilities.DynamicClientRegistration] : [];

    public void ConfigureDiscovery(
        OpenIddictServerEvents.HandleConfigurationRequestContext discovery,
        ProtocolFeatureContext context)
    {
        // OpenIddict has no DCR, so it never advertises the endpoint. Without
        // this entry an MCP client finds no registration_endpoint and gives up
        // on self-registration.
        if (context.Options.Mcp.Dcr.Enabled)
        {
            discovery.Metadata["registration_endpoint"] =
                JsonValue.Create(new Uri(
                    discovery.Issuer ?? new Uri("/", UriKind.Relative),
                    "connect/register").AbsoluteUri);
        }
    }
}
