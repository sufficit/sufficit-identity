using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;

namespace Sufficit.Identity.STS.Features;

/// <summary>
/// JWT-Secured Authorization Requests (RFC 9101): a signed <c>request</c>
/// parameter at the authorization and PAR endpoints, validated against the
/// client's registered keys and merged into the request.
/// </summary>
internal sealed class JarProtocolFeature : IProtocolFeature
{
    public string Name => "jar";

    public bool IsEnabled(SufficitIdentityOptions options) => options.Jar.Enabled;

    public IEnumerable<string> RuntimeCapabilities(SufficitIdentityOptions options) =>
        options.Jar.Enabled ? [ManagementRuntimeCapabilities.Jar] : [];

    public void Validate(SufficitIdentityOptions options)
    {
        var jar = options.Jar;
        if (jar.Enabled
            && (jar.MaxLifetimeSeconds is < 1 or > 600
                || jar.RemoteJwksMaxBytes is < 1024 or > 1_048_576
                || jar.RemoteJwksTimeoutSeconds is < 1 or > 30
                || jar.RemoteJwksCacheSeconds is < 1 or > 86_400
                || jar.RemoteJwksStaleSeconds is < 0 or > 86_400
                || jar.RemoteJwksMaxCacheEntries is < 1 or > 4096))
        {
            throw new InvalidOperationException(
                "JAR lifetime and remote JWKS timeout/size/cache settings are outside their supported security bounds.");
        }
    }

    public void ConfigureServer(OpenIddictServerBuilder server, ProtocolFeatureContext context)
    {
        if (!context.Options.Jar.Enabled)
        {
            return;
        }

        server.AddEventHandler(Jar.JarRequestObjectHandler
            .ExtractAuthorizationRequestObject.Descriptor);
        server.AddEventHandler(Jar.JarRequestObjectHandler
            .ExtractPushedAuthorizationRequestObject.Descriptor);
    }

    public void ConfigureDiscovery(
        OpenIddictServerEvents.HandleConfigurationRequestContext discovery,
        ProtocolFeatureContext context)
    {
        var jar = context.Options.Jar;
        if (!jar.Enabled)
        {
            return;
        }

        discovery.Metadata["request_parameter_supported"] = JsonValue.Create(true);
        discovery.Metadata["request_object_signing_alg_values_supported"] =
            System.Text.Json.JsonSerializer.SerializeToNode(
                jar.AllowedSigningAlgorithms
                    .OrderBy(algorithm => algorithm, StringComparer.Ordinal).ToArray());
    }
}
