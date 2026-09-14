using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;

namespace Sufficit.Identity.STS.Features;

/// <summary>
/// OAuth 2.0 Mutual-TLS client authentication and certificate-bound access
/// tokens (RFC 8705): endpoint aliases, native client authentication and the
/// rule that DPoP and mTLS sender constraints are not combined.
/// </summary>
/// <remarks>
/// The host must request and validate client certificates at the TLS layer;
/// the server project owns certificate forwarding from a trusted proxy.
/// private_key_jwt (RFC 7523) is enabled by OpenIddict unconditionally and is
/// not gated here.
/// </remarks>
internal sealed class MtlsProtocolFeature : IProtocolFeature
{
    public string Name => "mtls";

    public bool IsEnabled(SufficitIdentityOptions options) => options.Mtls.Enabled;

    public IEnumerable<string> RuntimeCapabilities(SufficitIdentityOptions options) =>
        options.Mtls.Enabled ? [ManagementRuntimeCapabilities.Mtls] : [];

    public void Validate(SufficitIdentityOptions options)
    {
        if (!options.Mtls.Enabled)
        {
            return;
        }

        if (options.Mtls.DeploymentMode == MtlsDeploymentMode.Unattested)
        {
            throw new InvalidOperationException(
                "mTLS is enabled without Sufficit:Identity:Mtls:DeploymentMode attestation.");
        }
        if (!string.IsNullOrWhiteSpace(options.Mtls.EndpointBaseUrl)
            && (!Uri.TryCreate(
                    options.Mtls.EndpointBaseUrl,
                    UriKind.Absolute,
                    out var endpointBase)
                || endpointBase is null
                || (endpointBase.Scheme != Uri.UriSchemeHttps
                    && endpointBase.Scheme != Uri.UriSchemeHttp)
                || !string.IsNullOrEmpty(endpointBase.UserInfo)
                || !string.IsNullOrEmpty(endpointBase.Query)
                || !string.IsNullOrEmpty(endpointBase.Fragment)))
        {
            throw new InvalidOperationException(
                "mTLS EndpointBaseUrl must be an absolute HTTP(S) URL without user information, query or fragment.");
        }
        if (options.Mtls.RevocationTimeoutSeconds is < 1 or > 30)
        {
            throw new InvalidOperationException(
                "mTLS RevocationTimeoutSeconds must be between 1 and 30 seconds.");
        }
        if (string.IsNullOrWhiteSpace(options.Mtls.ForwardedCertificateHeader)
            || options.Mtls.ForwardedCertificateHeader.Length > 64
            || options.Mtls.ForwardedCertificateHeader.Any(character =>
                !char.IsAsciiLetterOrDigit(character)
                && character != '-'))
        {
            throw new InvalidOperationException(
                "mTLS ForwardedCertificateHeader must be a non-empty HTTP token using only ASCII letters, digits and hyphens.");
        }
        var trustedNetworks =
            Mtls.MtlsClientCertificateForwarding.ParseNetworks(
                options.Mtls.TrustedProxyNetworks);
        if (options.Mtls.DeploymentMode == MtlsDeploymentMode.TrustedProxy
            && trustedNetworks.Count == 0)
        {
            throw new InvalidOperationException(
                "mTLS TrustedProxy deployment requires at least one dedicated Mtls:TrustedProxyNetworks entry.");
        }
    }

    public void ConfigureServer(OpenIddictServerBuilder server, ProtocolFeatureContext context)
    {
        var options = context.Options;
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

        if (options.Mtls.Enabled)
        {
            server.AddEventHandler(Mtls
                .RejectCombinedDpopAndMtlsSenderConstraints.Descriptor);
        }
    }
}
