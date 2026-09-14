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
        // -------------------------------------------------------------------
        // Discovery customizations. Logout capabilities are advertised
        // only when their provider-neutral dispatcher is enabled. The
        // application cookie and ID Tokens carry the same opaque OIDC
        // sid, so session-specific support follows each dispatcher
        // flag. Every other previously-advertised flag
        // (DPoP, JAR request object signing algorithms, request_uri/
        // request parameter support, claims parameter,
        // check_session_iframe, and a non-standard backchannel_logout_url
        // — that field is per-client registration metadata, not OP
        // discovery metadata) has been removed entirely: none of those
        // features are actually implemented either.
        // -------------------------------------------------------------------
        var featureContext = new Features.ProtocolFeatureContext(
            options,
            auxiliarySigningCredentials);
        server.AddEventHandler(OpenIddictServerHandlerDescriptor
            .CreateBuilder<OpenIddictServerEvents.HandleConfigurationRequestContext>()
            .UseInlineHandler(context =>
            {
                // Backchannel logout (OIDC Back-Channel Logout 1.0,
                // item 3.2 [L1]): advertised as supported ONLY when the
                // STS is configured to distribute logout_tokens to RPs
                // (BackchannelLogoutOptions.Enabled). When disabled,
                // publish `false` so OIDC clients natively skip the
                // flow instead of probing.
                context.Metadata["backchannel_logout_supported"] =
                    JsonValue.Create(options.BackchannelLogout.Enabled);
                context.Metadata["backchannel_logout_session_supported"] =
                    JsonValue.Create(options.BackchannelLogout.Enabled);

                // Frontchannel logout (OIDC Front-Channel Logout 1.0):
                // one-time iframe fan-out to registered RP logout URIs.
                context.Metadata["frontchannel_logout_supported"] =
                    JsonValue.Create(options.FrontchannelLogout.Enabled);
                context.Metadata["frontchannel_logout_session_supported"] =
                    JsonValue.Create(options.FrontchannelLogout.Enabled);

                // Optional protocol features publish their own metadata; see
                // Features/ProtocolFeatureCatalog.
                Features.ProtocolFeatureCatalog.ConfigureDiscovery(context, featureContext);

                // mTLS sender-constrained access tokens (RFC 8705, item
                // 3.4). Advertised ONLY when Mtls.Enabled — the host
                // must be configured for client certificates at the TLS
                // layer for this to be true (see MtlsOptions XML doc).
                // OpenIddict 7.6 publishes the RFC 8705 client
                // authentication methods, aliases and certificate-bound
                // token flag from the native mTLS configuration above.

                // Dynamic Client Registration (RFC 7591 §2 / OIDC
                // Discovery). OpenIddict ships no DCR, so it never
                // advertises the endpoint this STS implements. Without
                // this entry an MCP client reads the discovery
                // document, finds no registration_endpoint and gives up
                // on self-registration — the flow works only for
                // clients that already exist. Advertised strictly when
                // the endpoint is actually enabled.
                if (options.Mcp.Dcr.Enabled)
                {
                    context.Metadata["registration_endpoint"] =
                        JsonValue.Create(new Uri(
                            context.Issuer ?? new Uri("/", UriKind.Relative),
                            "connect/register").AbsoluteUri);
                }

                // OpenIddict attaches `iss` to every redirectable
                // authorization response (RFC 9207). Publish the
                // matching capability bit explicitly for FAPI clients.
                context.Metadata["authorization_response_iss_parameter_supported"] =
                    JsonValue.Create(true);

                // CIMD (draft-ietf-oauth-client-id-metadata-document):
                // advertise support only when the feature is on.
                context.Metadata["client_id_metadata_document_supported"] =
                    JsonValue.Create(
                        options.Mcp.ClientIdMetadataDocuments.Enabled);

                // Note: request_uri_parameter_supported and
                // require_pushed_authorization_requests are published
                // by OpenIddict itself based on the server options
                // (RequirePushedAuthorizationRequests above toggles the
                // latter). The PAR endpoint
                // (pushed_authorization_request_endpoint) is always
                // advertised once the endpoint URI is registered.

                // DPoP (RFC 9449, item 3.1). Advertised ONLY when
                // Dpop.Enabled: the STS validates DPoP proofs and
                // sender-constrains tokens. The signing-algorithms list
                // matches what DpopProofValidator accepts (EC P-256 and
                // RSA). OpenIddict 7.6 omits this entirely (no DPoP
                // support), so DiscoveryTests previously pinned its
                // absence — that assertion is updated alongside this.
                if (options.Dpop.Enabled)
                {
                    // dpop_signing_alg_values_supported is a JSON array
                    // of JWS alg names the AS accepts in DPoP proofs.
                    context.Metadata["dpop_signing_alg_values_supported"] =
                        System.Text.Json.JsonSerializer.SerializeToNode(
                            new[] { "ES256", "RS256" });
                }

                // JAR (RFC 9101): advertise request object support and
                // the accepted signing algorithms when enabled.
                if (options.Jar.Enabled)
                {
                    context.Metadata["request_parameter_supported"] =
                        JsonValue.Create(true);
                    context.Metadata["request_object_signing_alg_values_supported"] =
                        System.Text.Json.JsonSerializer.SerializeToNode(
                            options.Jar.AllowedSigningAlgorithms
                                .OrderBy(a => a, StringComparer.Ordinal).ToArray());
                }

                return default;
            })
            .SetOrder(OpenIddictServerHandlers.Discovery.AttachEndpoints.Descriptor.Order + 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build());
    }
}
