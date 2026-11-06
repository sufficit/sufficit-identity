using System.Text.Json;
using Microsoft.AspNetCore;
using Microsoft.Net.Http.Headers;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Sufficit.Identity.STS.Dpop;

/// <summary>
/// Attaches DPoP confirmation material after OpenIddict has prepared its token
/// principals. OpenIddict deliberately strips an inherited <c>cnf</c> claim in
/// its built-in preparation handlers, so DPoP binding must be added here.
/// </summary>
internal sealed class AttachDpopConfirmation : IOpenIddictServerHandler<ProcessSignInContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
            .UseSingletonHandler<AttachDpopConfirmation>()
            .SetOrder(PrepareUserCodePrincipal.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var thumbprint = context.Principal!.GetClaim(
            DpopProofValidator.BindingThumbprintClaimType);
        if (string.IsNullOrEmpty(thumbprint))
        {
            return ValueTask.CompletedTask;
        }

        var confirmation = JsonSerializer.SerializeToElement(new
        {
            jkt = thumbprint,
        });

        context.AccessTokenPrincipal?.SetClaim(Claims.Confirmation, confirmation);
        if (context.IssuedTokenType is TokenTypeIdentifiers.AccessToken)
        {
            context.IssuedTokenPrincipal?.SetClaim(Claims.Confirmation, confirmation);
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Uses the RFC 9449 token type for responses carrying a DPoP-bound token.
/// </summary>
internal sealed class AttachDpopTokenType : IOpenIddictServerHandler<ProcessSignInContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
            .UseSingletonHandler<AttachDpopTokenType>()
            .SetOrder(AttachSignInParameters.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var principal = context.AccessTokenPrincipal ??
            (context.IssuedTokenType is TokenTypeIdentifiers.AccessToken
                ? context.IssuedTokenPrincipal
                : null);

        if (principal is not null && HasDpopConfirmation(
                principal.GetClaim(Claims.Confirmation)))
        {
            context.Response.TokenType = "DPoP";
        }

        return ValueTask.CompletedTask;
    }

    private static bool HasDpopConfirmation(string? confirmation)
    {
        if (string.IsNullOrWhiteSpace(confirmation))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(confirmation);
            return document.RootElement.ValueKind is JsonValueKind.Object
                && document.RootElement.TryGetProperty(
                    DpopProofValidator.JktClaimMember,
                    out var member)
                && member.ValueKind is JsonValueKind.String
                && !string.IsNullOrWhiteSpace(member.GetString());
        }
        catch (JsonException)
        {
            return false;
        }
    }
}

/// <summary>
/// Accepts the RFC 9449 <c>Authorization: DPoP</c> scheme on UserInfo. The
/// OpenIddict ASP.NET Core adapter recognizes Bearer only in version 7.6.
/// </summary>
internal sealed class ExtractDpopUserInfoToken :
    IOpenIddictServerHandler<ExtractUserInfoRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractUserInfoRequestContext>()
            .UseSingletonHandler<ExtractDpopUserInfoToken>()
            .SetOrder(
                OpenIddictServerAspNetCoreHandlers
                    .ExtractAccessToken<ExtractUserInfoRequestContext>
                    .Descriptor.Order - 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ExtractUserInfoRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var request = context.Transaction.GetHttpRequest();
        var header = request?.Headers[HeaderNames.Authorization].ToString();
        if (header?.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase) is true)
        {
            context.Request!.AccessToken = header["DPoP ".Length..];
        }

        return ValueTask.CompletedTask;
    }
}

// Keep the original value per validation context: reference-token resolution
// replaces context.Token, and subject/actor validation share a transaction.
internal sealed class CaptureDpopWireToken : IOpenIddictServerHandler<ValidateTokenContext>
{
    private sealed record WireToken(string Value);
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<ValidateTokenContext, WireToken> Tokens = new();

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
            .UseSingletonHandler<CaptureDpopWireToken>()
            .SetOrder(OpenIddictServerHandlers.Protection.ValidateReferenceTokenIdentifier.Descriptor.Order - 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateTokenContext context)
    {
        Tokens.GetValue(context, current => new WireToken(current.Token));
        return ValueTask.CompletedTask;
    }

    internal static string? Get(ValidateTokenContext context) =>
        Tokens.TryGetValue(context, out var token) ? token.Value : null;
}

// Successful validation may be consumed by the dispatcher in this HTTP request
// only. Never place this handoff in a principal, cookie or distributed cache.
internal sealed record ValidatedDpopTokenProof(string Header, DpopProof Proof)
{
    private static readonly object ItemKey = new();

    internal static void Store(Microsoft.AspNetCore.Http.HttpRequest request, DpopProof proof) =>
        request.HttpContext.Items[ItemKey] = new ValidatedDpopTokenProof(request.Headers["DPoP"].ToString(), proof);

    internal static DpopProof? Take(Microsoft.AspNetCore.Http.HttpContext context)
    {
        if (!context.Items.Remove(ItemKey, out var value)
            || value is not ValidatedDpopTokenProof validated
            || !string.Equals(validated.Header, context.Request.Headers["DPoP"].ToString(), StringComparison.Ordinal))
            return null;
        return validated.Proof;
    }
}

/// <summary>
/// Validates DPoP proof-of-possession for access tokens consumed by the STS
/// itself. OpenIddict 7.6 validates mTLS <c>cnf.x5t#S256</c> natively but does
/// not understand <c>cnf.jkt</c>.
/// </summary>
internal sealed class ValidateDpopAccessTokenProof :
    IOpenIddictServerHandler<ValidateTokenContext>
{
    private readonly DpopProofValidator _validator;

    public ValidateDpopAccessTokenProof(DpopProofValidator validator) =>
        _validator = validator;

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
            .UseSingletonHandler<ValidateDpopAccessTokenProof>()
            .SetOrder(
                OpenIddictServerHandlers.Protection.ValidateProofOfPossession
                    .Descriptor.Order - 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidateTokenContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.DisableProofOfPossessionValidation ||
            context.Principal?.GetTokenType() is not TokenTypeIdentifiers.AccessToken)
        {
            return;
        }

        var confirmation = context.Principal.GetClaim(Claims.Confirmation);
        if (string.IsNullOrEmpty(confirmation))
        {
            return;
        }

        string? boundThumbprint;
        try
        {
            using var document = JsonDocument.Parse(confirmation);
            boundThumbprint = document.RootElement.TryGetProperty(
                    DpopProofValidator.JktClaimMember,
                    out var member)
                ? member.GetString()
                : null;
        }
        catch (JsonException)
        {
            return; // Let OpenIddict's native validation reject malformed cnf.
        }

        if (string.IsNullOrEmpty(boundThumbprint))
        {
            return; // Not DPoP (e.g. native mTLS x5t#S256).
        }

        // Suppress OpenIddict's mTLS-only validator for cnf.jkt. This handler
        // fully validates the DPoP proof or rejects the request itself.
        context.DisableProofOfPossessionValidation = true;

        var request = context.Transaction.GetHttpRequest();
        if (request is null)
        {
            context.Reject(error: Errors.InvalidToken,
                description: "The HTTP request required for DPoP validation is unavailable.");
            return;
        }

        var wireToken = CaptureDpopWireToken.Get(context);
        if (string.IsNullOrEmpty(wireToken))
        {
            context.Reject(Errors.InvalidToken, "The original token required for DPoP validation is unavailable.");
            return;
        }

        var proof = await _validator.ValidateAsync(
            request.Headers["DPoP"].ToString(),
            request.Method,
            request.Scheme + "://" + request.Host + request.PathBase + request.Path,
            expectedNonce: null,
            context.CancellationToken,
            // For reference tokens, context.Token is the resolved internal
            // payload. RFC 9449 ath binds the opaque value the client sent.
            accessToken: wireToken);

        if (proof is null || !string.Equals(
                proof.KeyThumbprint,
                boundThumbprint,
                StringComparison.Ordinal))
        {
            context.Reject(error: Errors.InvalidToken,
                description: "A valid DPoP proof bound to this access token is required.");
            return;
        }

        if (context.Request?.IsTokenExchangeGrantType() is true)
            ValidatedDpopTokenProof.Store(request, proof);
    }
}
