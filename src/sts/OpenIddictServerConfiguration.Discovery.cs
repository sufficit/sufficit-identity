using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.STS.Metrics;
using Sufficit.Identity.Vault;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS;

public static partial class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds discovery metadata for the capabilities this STS implements beyond
    /// what OpenIddict publishes itself.
    /// </summary>
    private static void ConfigureDiscoveryMetadata(
        OpenIddictServerBuilder server,
        SufficitIdentityOptions options,
        SigningCredentials auxiliarySigningCredentials)
    {
        // Each optional protocol feature publishes its own metadata, including
        // "not supported" values while disabled (see Features/). Only
        // metadata that belongs to no single feature is set here.
        var featureContext = new Features.ProtocolFeatureContext(
            options,
            auxiliarySigningCredentials);
        server.AddEventHandler(OpenIddictServerHandlerDescriptor
            .CreateBuilder<OpenIddictServerEvents.HandleConfigurationRequestContext>()
            .UseInlineHandler(context =>
            {
                // Optional protocol features publish their own metadata; see
                // Features/ProtocolFeatureCatalog.
                Features.ProtocolFeatureCatalog.ConfigureDiscovery(context, featureContext);

                // OpenIddict attaches `iss` to every redirectable
                // authorization response (RFC 9207). Publish the
                // matching capability bit explicitly for FAPI clients.
                context.Metadata["authorization_response_iss_parameter_supported"] =
                    JsonValue.Create(true);

                // Note: request_uri_parameter_supported and
                // require_pushed_authorization_requests are published
                // by OpenIddict itself based on the server options
                // (RequirePushedAuthorizationRequests above toggles the
                // latter). The PAR endpoint
                // (pushed_authorization_request_endpoint) is always
                // advertised once the endpoint URI is registered.

                return default;
            })
            .SetOrder(OpenIddictServerHandlers.Discovery.AttachEndpoints.Descriptor.Order + 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build());
    }
}
