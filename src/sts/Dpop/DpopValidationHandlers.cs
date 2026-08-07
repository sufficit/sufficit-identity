using System.Text.Json;
using Microsoft.AspNetCore;
using Microsoft.Net.Http.Headers;
using OpenIddict.Abstractions;
using OpenIddict.Validation;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.OpenIddictValidationEvents;

namespace Sufficit.Identity.STS.Dpop;

internal sealed class ExtractDpopValidationToken :
    IOpenIddictValidationHandler<ProcessAuthenticationContext>
{
    internal const string RawAccessTokenProperty =
        "Sufficit.Identity.DPoP.RawAccessToken";
    public static OpenIddictValidationHandlerDescriptor Descriptor { get; } =
        OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
            .UseSingletonHandler<ExtractDpopValidationToken>()
            .SetOrder(OpenIddictValidationAspNetCoreHandlers
                .ExtractAccessTokenFromAuthorizationHeader.Descriptor.Order - 500)
            .SetType(OpenIddictValidationHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ProcessAuthenticationContext context)
    {
        var request = context.Transaction.GetHttpRequest();
        var header = request?.Headers[HeaderNames.Authorization].ToString();
        if (header?.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase) is true)
        {
            context.AccessToken = header["DPoP ".Length..];
            context.Transaction.Properties[RawAccessTokenProperty] =
                context.AccessToken;
        }
        return ValueTask.CompletedTask;
    }
}

internal sealed class ValidateDpopApiAccessTokenProof :
    IOpenIddictValidationHandler<ValidateTokenContext>
{
    private readonly DpopProofValidator _validator;

    public ValidateDpopApiAccessTokenProof(DpopProofValidator validator) =>
        _validator = validator;

    public static OpenIddictValidationHandlerDescriptor Descriptor { get; } =
        OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
            .UseSingletonHandler<ValidateDpopApiAccessTokenProof>()
            .SetOrder(OpenIddictValidationHandlers.Protection.ValidateProofOfPossession
                .Descriptor.Order - 500)
            .SetType(OpenIddictValidationHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidateTokenContext context)
    {
        if (context.DisableProofOfPossessionValidation
            || context.Principal?.GetTokenType() is not TokenTypeIdentifiers.AccessToken)
            return;

        var confirmation = context.Principal.GetClaim(Claims.Confirmation);
        if (string.IsNullOrWhiteSpace(confirmation)) return;

        string? boundThumbprint;
        try
        {
            using var document = JsonDocument.Parse(confirmation);
            boundThumbprint = document.RootElement.TryGetProperty(
                DpopProofValidator.JktClaimMember, out var member)
                ? member.GetString()
                : null;
        }
        catch (JsonException)
        {
            return;
        }
        if (string.IsNullOrWhiteSpace(boundThumbprint)) return;

        context.DisableProofOfPossessionValidation = true;
        var request = context.Transaction.GetHttpRequest();
        if (request is null)
        {
            context.Reject(Errors.InvalidToken,
                "The HTTP request required for DPoP validation is unavailable.");
            return;
        }

        var proof = await _validator.ValidateAsync(
            request.Headers["DPoP"].ToString(),
            request.Method,
            request.Scheme + "://" + request.Host + request.PathBase + request.Path,
            expectedNonce: null,
            context.CancellationToken,
            accessToken: context.Transaction.Properties.TryGetValue(
                    ExtractDpopValidationToken.RawAccessTokenProperty,
                    out var rawToken)
                ? rawToken as string
                : context.Request?.AccessToken ?? context.Token);
        if (proof is null || !string.Equals(
            proof.KeyThumbprint, boundThumbprint, StringComparison.Ordinal))
            context.Reject(Errors.InvalidToken,
                "A valid DPoP proof bound to this access token is required.");
    }
}
