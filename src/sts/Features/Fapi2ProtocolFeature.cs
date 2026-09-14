using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;

namespace Sufficit.Identity.STS.Features;

/// <summary>
/// FAPI 2.0 Security Profile for the configured clients: sender-constrained
/// tokens, PAR and tightened code and request_uri lifetimes.
/// </summary>
internal sealed class Fapi2ProtocolFeature : IProtocolFeature
{
    public string Name => "fapi2";

    public bool IsEnabled(SufficitIdentityOptions options) => options.Fapi2.Enabled;

    public IEnumerable<string> RuntimeCapabilities(SufficitIdentityOptions options) =>
        options.Fapi2.Enabled ? [ManagementRuntimeCapabilities.Fapi2] : [];

    public void Validate(SufficitIdentityOptions options)
    {
        var fapi = options.Fapi2;
        if (!fapi.Enabled)
        {
            return;
        }

        if (fapi.ClientIds.Count == 0)
            throw new InvalidOperationException(
                "FAPI 2.0 is enabled but Sufficit:Identity:Fapi2:ClientIds is empty.");
        if (fapi.AuthorizationCodeLifetimeSeconds is < 1 or > 60)
            throw new InvalidOperationException(
                "FAPI 2.0 authorization-code lifetime must be between 1 and 60 seconds.");
        if (fapi.PushedAuthorizationRequestLifetimeSeconds is < 1 or >= 600)
            throw new InvalidOperationException(
                "FAPI 2.0 PAR request_uri lifetime must be between 1 and 599 seconds.");
        if (fapi.SenderConstraint == Fapi2SenderConstraint.Dpop && !options.Dpop.Enabled)
            throw new InvalidOperationException(
                "FAPI 2.0 SenderConstraint=DPoP requires Sufficit:Identity:Dpop:Enabled=true.");
        if (fapi.SenderConstraint == Fapi2SenderConstraint.Mtls && !options.Mtls.Enabled)
            throw new InvalidOperationException(
                "FAPI 2.0 SenderConstraint=mTLS requires Sufficit:Identity:Mtls:Enabled=true.");
        // Per-client mTLS bindings are persisted as public X.509 JWKs and
        // validated at request time; operators rotate them through the
        // management API, so startup does not require them.
    }

    public void ConfigureServer(OpenIddictServerBuilder server, ProtocolFeatureContext context)
    {
        var fapi = context.Options.Fapi2;
        if (!fapi.Enabled)
        {
            return;
        }

        // These OpenIddict lifetimes are global. Tightening them for all
        // clients is backward compatible and keeps a profiled client from
        // receiving a five-minute code or an hour-long PAR request URI.
        server.SetAuthorizationCodeLifetime(TimeSpan.FromSeconds(
            fapi.AuthorizationCodeLifetimeSeconds));
        server.Configure(serverOptions =>
            serverOptions.RequestTokenLifetime = TimeSpan.FromSeconds(
                fapi.PushedAuthorizationRequestLifetimeSeconds));

        server.AddEventHandler(Fapi.ValidateFapiAuthorizationRequest.Descriptor);
        server.AddEventHandler(Fapi.ValidateFapiPushedAuthorizationRequest.Descriptor);
        server.AddEventHandler(Fapi.ValidateFapiTokenRequest.Descriptor);
    }
}
