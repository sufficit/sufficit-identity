using Microsoft.AspNetCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using System.Text.Json;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Sufficit.Identity.STS.Fapi;

internal static class Fapi2Policy
{
    public static bool Applies(Fapi2Options options, string? clientId) =>
        options.Enabled &&
        !string.IsNullOrWhiteSpace(clientId) &&
        options.ClientIds.Contains(clientId);

    public static bool HasValidDpopJkt(OpenIddictRequest request)
    {
        var value = (string?)request["dpop_jkt"];
        if (string.IsNullOrWhiteSpace(value)) return false;
        try
        {
            return Base64UrlEncoder.DecodeBytes(value).Length == 32;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static bool UsesPrivateKeyJwt(
        BaseContext context,
        string? issuer)
    {
        if (context.Transaction.Request?.ClientAssertion is { Length: > 0 } assertion)
        {
            // OpenIddict validates the assertion, including signature, iss and
            // aud, before our late profile handlers run. FAPI narrows the
            // allowed audience further: it must be the issuer identifier as a
            // JSON string (not an array and not an endpoint URL).
            try
            {
                _ = new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(assertion);
                var segments = assertion.Split('.');
                if (segments.Length != 3) return false;
                using var payload = JsonDocument.Parse(
                    Base64UrlEncoder.DecodeBytes(segments[1]));
                return Uri.TryCreate(issuer, UriKind.Absolute, out var uri) &&
                    payload.RootElement.TryGetProperty("aud", out var audience) &&
                    audience.ValueKind == JsonValueKind.String &&
                    string.Equals(audience.GetString(), uri.AbsoluteUri,
                        StringComparison.Ordinal);
            }
            catch (Exception exception) when (
                exception is ArgumentException or JsonException)
            {
                return false;
            }
        }

        return false;
    }
}

/// <summary>Requires PAR for every profiled authorization request.</summary>
internal sealed class ValidateFapiAuthorizationRequest :
    IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    private readonly Fapi2Options _options;
    public ValidateFapiAuthorizationRequest(Fapi2Options options) => _options = options;

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor
            .CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseSingletonHandler<ValidateFapiAuthorizationRequest>()
            .SetOrder(Authentication.ValidatePushedAuthorizationRequestsRequirement
                .Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        if (Fapi2Policy.Applies(_options, context.Request.ClientId) &&
            string.IsNullOrWhiteSpace(context.Request.RequestUri))
        {
            context.Reject(
                Errors.InvalidRequest,
                "This client must use a pushed authorization request (PAR).",
                "https://openid.net/specs/fapi-security-profile-2_0.html#name-authorization-endpoint-flow");
        }
        return ValueTask.CompletedTask;
    }
}

/// <summary>Applies the FAPI authorization-flow rules at the PAR endpoint.</summary>
internal sealed class ValidateFapiPushedAuthorizationRequest :
    IOpenIddictServerHandler<ValidatePushedAuthorizationRequestContext>
{
    private readonly IOpenIddictApplicationManager _applications;
    private readonly Fapi2Options _options;
    private readonly string? _issuer;
    private readonly Mtls.IMtlsClientCertificatePolicy _mtlsPolicy;

    public ValidateFapiPushedAuthorizationRequest(
        IOpenIddictApplicationManager applications,
        SufficitIdentityOptions options,
        Mtls.IMtlsClientCertificatePolicy mtlsPolicy)
    {
        _applications = applications;
        _options = options.Fapi2;
        _issuer = options.Issuer;
        _mtlsPolicy = mtlsPolicy;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor
            .CreateBuilder<ValidatePushedAuthorizationRequestContext>()
            .UseScopedHandler<ValidateFapiPushedAuthorizationRequest>()
            .SetOrder(Authentication.ValidatePushedAuthorizedParty.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidatePushedAuthorizationRequestContext context)
    {
        if (!Fapi2Policy.Applies(_options, context.Request.ClientId)) return;

        var application = await _applications.FindByClientIdAsync(
            context.Request.ClientId!, context.CancellationToken);
        if (application is null || !string.Equals(
                await _applications.GetClientTypeAsync(application, context.CancellationToken),
                ClientTypes.Confidential,
                StringComparison.Ordinal))
        {
            context.Reject(Errors.UnauthorizedClient,
                "FAPI 2.0 is restricted to confidential clients.");
            return;
        }

        var httpContext = context.Transaction.GetHttpRequest()?.HttpContext;
        var mtls = httpContext is null
            ? new Mtls.MtlsClientCertificateDecision(false)
            : await _mtlsPolicy.EvaluateAsync(
                httpContext,
                context.Request.ClientId,
                context.CancellationToken);
        if (!Fapi2Policy.UsesPrivateKeyJwt(context, _issuer) && !mtls.Allowed)
        {
            context.Reject(Errors.InvalidClient,
                "FAPI 2.0 clients must authenticate with private_key_jwt or mutual TLS.");
            return;
        }

        if (!context.Request.HasResponseType(ResponseTypes.Code))
        {
            context.Reject(Errors.UnsupportedResponseType,
                "FAPI 2.0 authorization requests must use response_type=code.");
            return;
        }

        if (string.IsNullOrWhiteSpace(context.Request.RedirectUri))
        {
            context.Reject(Errors.InvalidRequest,
                "A redirect_uri is required in the pushed authorization request.");
            return;
        }

        if (string.IsNullOrWhiteSpace(context.Request.CodeChallenge) ||
            !string.Equals(context.Request.CodeChallengeMethod,
                CodeChallengeMethods.Sha256, StringComparison.Ordinal))
        {
            context.Reject(Errors.InvalidRequest,
                "FAPI 2.0 requires PKCE with code_challenge_method=S256.");
            return;
        }

        if (_options.SenderConstraint == Fapi2SenderConstraint.Dpop &&
            !Fapi2Policy.HasValidDpopJkt(context.Request))
        {
            context.Reject(Errors.InvalidRequest,
                "A valid dpop_jkt parameter is required to bind the authorization code.");
        }
    }
}

/// <summary>Rejects weak client authentication at the token endpoint.</summary>
internal sealed class ValidateFapiTokenRequest :
    IOpenIddictServerHandler<ValidateTokenRequestContext>
{
    private readonly Fapi2Options _options;
    private readonly string? _issuer;
    private readonly Mtls.IMtlsClientCertificatePolicy _mtlsPolicy;
    public ValidateFapiTokenRequest(
        SufficitIdentityOptions options,
        Mtls.IMtlsClientCertificatePolicy mtlsPolicy)
    {
        _options = options.Fapi2;
        _issuer = options.Issuer;
        _mtlsPolicy = mtlsPolicy;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor
            .CreateBuilder<ValidateTokenRequestContext>()
            .UseScopedHandler<ValidateFapiTokenRequest>()
            .SetOrder(Exchange.ValidateAuthentication.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidateTokenRequestContext context)
    {
        if (!Fapi2Policy.Applies(_options, context.Request.ClientId))
            return;

        var httpContext = context.Transaction.GetHttpRequest()?.HttpContext;
        var mtls = httpContext is null
            ? new Mtls.MtlsClientCertificateDecision(false)
            : await _mtlsPolicy.EvaluateAsync(
                httpContext,
                context.Request.ClientId,
                context.CancellationToken);
        if (!Fapi2Policy.UsesPrivateKeyJwt(context, _issuer) && !mtls.Allowed)
        {
            context.Reject(Errors.InvalidClient,
                "FAPI 2.0 clients must authenticate with private_key_jwt or mutual TLS.");
        }
        else if (_options.SenderConstraint == Fapi2SenderConstraint.Mtls
                 && !mtls.Allowed)
        {
            context.Reject(Errors.InvalidClient,
                "This FAPI 2.0 client requires mutual-TLS sender-constrained tokens.");
        }

    }
}
