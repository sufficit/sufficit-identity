using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.STS.Metrics;
using Sufficit.Identity.Vault;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Sufficit.Identity.Application.Security;

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

                // RFC 8414: required alongside private_key_jwt, which every
                // client with a registered key set can use, and FAPI 2.0 fails
                // a server without it
                // (FAPI2CheckDiscEndpointTokenEndpointAuthSigningAlgValuesSupported).
                // The assertion is verified against the client's own key, so
                // the announced set is the asymmetric one the profile expects
                // plus RS256 for clients that predate it. Symmetric algorithms
                // are deliberately absent: client_secret_jwt is not offered.
                context.Metadata["token_endpoint_auth_signing_alg_values_supported"] =
                    new JsonArray("PS256", "ES256", "RS256");

                // OIDC Core 3.1.2.1 / RFC 8414: the assurance levels a client
                // may ask for through acr_values. Announced because the
                // authorization endpoint acts on them — it runs the ceremony
                // when the session is below what was asked. The list stops at
                // loa3: a phishing-resistant session satisfies it, but it is
                // not separately requestable, so advertising it would promise
                // a level the ceremony cannot deliberately reach.
                var authenticationContextClasses =
                    new ConfigurableAuthenticationContextClassMapper(
                        options.AuthenticationContext);
                context.Metadata["acr_values_supported"] = new JsonArray(
                    authenticationContextClasses.Map(CaepAssuranceLevel.Loa1),
                    authenticationContextClasses.Map(CaepAssuranceLevel.Loa2),
                    authenticationContextClasses.Map(CaepAssuranceLevel.Loa3));

                // Note: request_uri_parameter_supported and
                // require_pushed_authorization_requests are published
                // by OpenIddict itself based on the server options
                // (RequirePushedAuthorizationRequests above toggles the
                // latter). The PAR endpoint
                // (pushed_authorization_request_endpoint) is always
                // advertised once the endpoint URI is registered.

                return default;
            })
            // After OpenIddict published the client authentication methods:
            // the signing algorithms below are only announced when a signed
            // assertion is actually accepted.
            .SetOrder(OpenIddictServerHandlers.Discovery
                .AttachClientAuthenticationMethods.Descriptor.Order + 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build());
    }
}
