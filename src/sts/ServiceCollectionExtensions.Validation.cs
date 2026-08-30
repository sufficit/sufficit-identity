using System.Security.Cryptography.X509Certificates;
using System.Security.Claims;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using MySqlConnector;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Validation.AspNetCore;
using Sufficit.Identity.Application.Branding;
using Sufficit.Identity.Core;
using Sufficit.Identity.Core.Branding;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Application.Diagnostics;
using Sufficit.Identity.STS.Diagnostics;
using Sufficit.Identity.STS.Email;
using Sufficit.Identity.STS.Metrics;
using Sufficit.Identity.Core.Metrics;
using Sufficit.Identity.Management;
using Sufficit.Identity.STS.Integrations;
using Sufficit.Identity.Vault;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS;

/// <summary>
/// DI extensions that wire up the Sufficit Identity STS server
/// (ASP.NET Core Identity + OpenIddict server/validation).

public static partial class ServiceCollectionExtensions
{
    private static void ValidateAdvancedProtocolOptions(SufficitIdentityOptions options)
    {
        ValidateTokenFormatMap(
            options.Tokens.AccessTokenFormatsByClient,
            "Tokens:AccessTokenFormatsByClient");
        ValidateTokenFormatMap(
            options.Tokens.AccessTokenFormatsByResource,
            "Tokens:AccessTokenFormatsByResource");

        if (options.Mtls.Enabled
            && options.Mtls.DeploymentMode == MtlsDeploymentMode.Unattested)
        {
            throw new InvalidOperationException(
                "mTLS is enabled without Sufficit:Identity:Mtls:DeploymentMode attestation.");
        }
        if (options.Mtls.Enabled)
        {
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
            if (string.IsNullOrWhiteSpace(
                    options.Mtls.ForwardedCertificateHeader)
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

        if (options.Fapi2.Enabled)
        {
            if (options.Fapi2.ClientIds.Count == 0)
                throw new InvalidOperationException(
                    "FAPI 2.0 is enabled but Sufficit:Identity:Fapi2:ClientIds is empty.");
            if (options.Fapi2.AuthorizationCodeLifetimeSeconds is < 1 or > 60)
                throw new InvalidOperationException(
                    "FAPI 2.0 authorization-code lifetime must be between 1 and 60 seconds.");
            if (options.Fapi2.PushedAuthorizationRequestLifetimeSeconds is < 1 or >= 600)
                throw new InvalidOperationException(
                    "FAPI 2.0 PAR request_uri lifetime must be between 1 and 599 seconds.");
            if (options.Fapi2.SenderConstraint == Fapi2SenderConstraint.Dpop &&
                !options.Dpop.Enabled)
                throw new InvalidOperationException(
                    "FAPI 2.0 SenderConstraint=DPoP requires Sufficit:Identity:Dpop:Enabled=true.");
            if (options.Fapi2.SenderConstraint == Fapi2SenderConstraint.Mtls &&
                !options.Mtls.Enabled)
                throw new InvalidOperationException(
                    "FAPI 2.0 SenderConstraint=mTLS requires Sufficit:Identity:Mtls:Enabled=true.");
            // Per-client mTLS bindings are persisted as public X.509 JWKs and
            // validated at request time. Startup cannot require them from the
            // legacy configuration dictionary because operators rotate and
            // revoke those bindings through the management API.
        }

        if (options.Jarm.Enabled)
        {
            if (options.Jarm.LifetimeSeconds is < 1 or > 600)
                throw new InvalidOperationException(
                    "JARM response lifetime must be between 1 and 600 seconds.");
            if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out _))
                throw new InvalidOperationException(
                    "JARM requires an explicit absolute Sufficit:Identity:Issuer.");
        }

        if (options.SharedSignals.Enabled)
        {
            if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out var issuer) ||
                issuer.Scheme != Uri.UriSchemeHttps)
                throw new InvalidOperationException(
                    "SSF/CAEP requires an explicit HTTPS Sufficit:Identity:Issuer.");
            if (issuer.AbsolutePath != "/")
                throw new InvalidOperationException(
                    "This SSF/CAEP transmitter currently requires an issuer without a path component.");

            var duplicate = options.SharedSignals.Receivers
                .Where(receiver => !string.IsNullOrWhiteSpace(receiver.Id))
                .GroupBy(receiver => receiver.Id, StringComparer.Ordinal)
                .FirstOrDefault(group => group.Count() > 1);
            if (duplicate is not null)
                throw new InvalidOperationException(
                    $"SSF/CAEP receiver id '{duplicate.Key}' is duplicated.");

            foreach (var receiver in options.SharedSignals.Receivers)
            {
                if (string.IsNullOrWhiteSpace(receiver.Id) ||
                    string.IsNullOrWhiteSpace(receiver.Audience) ||
                    !Uri.TryCreate(receiver.Endpoint, UriKind.Absolute, out var endpoint) ||
                    endpoint.Scheme != Uri.UriSchemeHttps ||
                    endpoint.Fragment.Length != 0)
                    throw new InvalidOperationException(
                        "Each SSF/CAEP receiver requires an id, audience and fragment-free HTTPS endpoint.");
            }
        }
    }

    private static void ValidateTokenFormatMap(
        IReadOnlyDictionary<string, AccessTokenStorageMode> values,
        string setting)
    {
        if (values.Count > 4096
            || values.Keys.Any(key =>
                string.IsNullOrWhiteSpace(key)
                || key.Length > 512
                || !string.Equals(key, key.Trim(), StringComparison.Ordinal)))
        {
            throw new InvalidOperationException(
                $"Sufficit:Identity:{setting} contains an invalid or excessive exact-match token-format mapping.");
        }
    }
}
