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
    /// Registers the RFC 8705 mTLS endpoint aliases and certificate-bound client authentication when mTLS is enabled.
    /// </summary>
    private static void ConfigureMtlsEndpoints(
        OpenIddictServerBuilder server,
        SufficitIdentityOptions options)
    {
        // -------------------------------------------------------------------
        // Mutual TLS (mTLS) endpoint aliases (RFC 8705, item 3.4).
        // Opt-in via Sufficit:Identity:Mtls:Enabled — mTLS requires the
        // HOST to request/validate client certificates at the TLS layer,
        // so the aliased paths must be registered as real protocol
        // endpoints in addition to being published in discovery.
        // private_key_jwt
        // (RFC 7523) is enabled by OpenIddict unconditionally and is
        // NOT gated here — it is the OTHER strong client-auth method.
        // -------------------------------------------------------------------
        if (options.Mtls.Enabled)
        {
            // Alias metadata alone does not map an ASP.NET endpoint.
            // Keep the original endpoints for compatible clients and
            // explicitly add the RFC 8705 aliases to OpenIddict's
            // endpoint matcher.
            server.SetTokenEndpointUris(
                      "connect/token",
                      "connect/token/mtls")
                  .SetIntrospectionEndpointUris(
                      "connect/introspect",
                      "connect/introspect/mtls")
                  .SetRevocationEndpointUris(
                      "connect/revocation",
                      "connect/revocation/mtls")
                  .SetDeviceAuthorizationEndpointUris(
                      "connect/deviceauthorization",
                      "connect/deviceauthorization/mtls")
                  .SetUserInfoEndpointUris(
                      "connect/userinfo",
                      "connect/userinfo/mtls")
                  .SetPushedAuthorizationEndpointUris(
                      "connect/par",
                      "connect/par/mtls");

            // OpenIddict 7.6 implements both RFC 8705 client
            // authentication methods itself. Enabling the native
            // validators is essential: aliases and a cnf claim alone
            // do not authenticate a confidential client.
            server.EnableSelfSignedTlsClientAuthentication();
            var certificateAuthorities =
                Mtls.MtlsCertificateAuthorityLoader.Load(
                    options.Mtls.TrustedCertificateAuthorityPaths);
            if (certificateAuthorities.Count > 0)
            {
                server.EnablePublicKeyInfrastructureTlsClientAuthentication(
                    certificateAuthorities,
                    policy => Mtls.MtlsCertificateAuthorityLoader
                        .ConfigurePolicy(policy, options.Mtls));
            }

            // Let OpenIddict create and enforce RFC 8705 cnf claims
            // for access tokens and introspection responses.
            server.UseClientCertificateBoundAccessTokens();

            // MTLS alias setters require ABSOLUTE URI strings (unlike
            // SetTokenEndpointUris, which accepts relative paths and
            // resolves them against the issuer). Build absolute URIs
            // from the dedicated public mTLS base when configured;
            // otherwise fall back to the issuer. This lets a proxy
            // isolate certificate handshakes on a dedicated port
            // without changing the ordinary issuer or clients.
            var mtlsIssuer = string.IsNullOrWhiteSpace(options.Issuer)
                ? "https://localhost/"
                : options.Issuer;
            var mtlsBase = string.IsNullOrWhiteSpace(
                options.Mtls.EndpointBaseUrl)
                ? new Uri(mtlsIssuer, UriKind.Absolute)
                : new Uri(options.Mtls.EndpointBaseUrl, UriKind.Absolute);

            server.SetMtlsTokenEndpointAliasUri(new Uri(mtlsBase, "connect/token/mtls").AbsoluteUri)
                  .SetMtlsIntrospectionEndpointAliasUri(new Uri(mtlsBase, "connect/introspect/mtls").AbsoluteUri)
                  .SetMtlsRevocationEndpointAliasUri(new Uri(mtlsBase, "connect/revocation/mtls").AbsoluteUri)
                  .SetMtlsDeviceAuthorizationEndpointAliasUri(new Uri(mtlsBase, "connect/deviceauthorization/mtls").AbsoluteUri)
                  .SetMtlsUserInfoEndpointAliasUri(new Uri(mtlsBase, "connect/userinfo/mtls").AbsoluteUri)
                  .SetMtlsPushedAuthorizationEndpointAliasUri(new Uri(mtlsBase, "connect/par/mtls").AbsoluteUri);
        }
    }
}
