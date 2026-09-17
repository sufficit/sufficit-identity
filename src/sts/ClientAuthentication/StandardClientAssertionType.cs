using Microsoft.IdentityModel.JsonWebTokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Sufficit.Identity.STS.ClientAuthentication;

/// <summary>
/// <para>
/// Accepts <c>private_key_jwt</c> client assertions that carry the ordinary
/// <c>typ</c> of a JWT, or no <c>typ</c> at all.
/// </para>
/// <para>
/// RFC 7523 defines no media type for a client assertion, and the libraries
/// clients actually use — Nimbus, jose4j, MSAL, and the OpenID conformance
/// suite — sign it with <c>typ: JWT</c> or omit the header. OpenIddict only
/// accepts its own <c>client-authentication+jwt</c>, so every standard client
/// was answered with <c>invalid_client</c> ("the specified token is not of the
/// expected type"). The FAPI 2.0 plan of the conformance suite could not get
/// past its first request.
/// </para>
/// <para>
/// The <c>typ</c> check is dropped only for a client assertion, and only after
/// this handler has checked the header itself: a token typed as something else
/// (an access token, a request object, an ID token) still goes to OpenIddict's
/// own validation and is refused. Type confusion needs more than a header
/// anyway — the assertion is verified against the calling client's registered
/// keys, and the issuer and the subject both have to be that client
/// (RFC 7523, section 3).
/// </para>
/// </summary>
internal sealed class AcceptStandardClientAssertionType
    : IOpenIddictServerHandler<ValidateTokenContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
            .UseSingletonHandler<AcceptStandardClientAssertionType>()
            .SetOrder(Protection.ValidateIdentityModelToken.Descriptor.Order - 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateTokenContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Only the client-assertion validation declares this type; every other
        // token validation is left exactly as OpenIddict configured it.
        if (context.TokenValidationParameters?.ValidTypes is not { } types
            || !types.Contains(
                JsonWebTokenTypes.ClientAuthentication,
                StringComparer.Ordinal))
        {
            return default;
        }

        if (string.IsNullOrEmpty(context.Token))
        {
            return default;
        }

        JsonWebToken token;
        try
        {
            token = new JsonWebToken(context.Token);
        }
        catch (ArgumentException)
        {
            // Not a JWT at all: OpenIddict rejects it a moment later.
            return default;
        }

        var declaredType = token.TryGetHeaderValue<string>(
            JwtHeaderParameterNames.Typ,
            out var value) ? value : null;

        if (!IsStandardJwtType(declaredType))
        {
            return default;
        }

        if (!IsSelfIssued(token, context.Request?.ClientId))
        {
            return default;
        }

        // ValidTypes is how Microsoft.IdentityModel enforces typ; clearing it
        // skips only that check, keeping signature, lifetime and audience
        // validation in place.
        context.TokenValidationParameters.ValidTypes = null;
        context.Transaction.Properties[RelaxedProperty] = true;

        return default;
    }

    /// <summary>
    /// Marks the transaction whose client assertion was accepted with a
    /// standard <c>typ</c>, so the companion handler knows the principal it
    /// sees came from this path and from nowhere else.
    /// </summary>
    internal const string RelaxedProperty =
        "Sufficit.Identity.STS:standard-client-assertion";

    /// <summary>
    /// Whether the header is absent or the generic JWT type. Anything else
    /// (<c>at+jwt</c>, <c>oauth-authz-req+jwt</c>, ...) names a token meant for
    /// a different purpose and is left to OpenIddict to refuse.
    /// </summary>
    private static bool IsStandardJwtType(string? declaredType) =>
        string.IsNullOrEmpty(declaredType)
        || string.Equals(declaredType, JwtConstants.HeaderType, StringComparison.OrdinalIgnoreCase)
        || string.Equals(declaredType, "application/jwt", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// RFC 7523 section 3: a client authenticating itself issues the assertion
    /// to itself, so <c>iss</c> and <c>sub</c> are both the client identifier.
    /// A request object signed by the same key has no such subject, which is
    /// what keeps one from being replayed as the other. The <c>client_id</c>
    /// parameter is optional when the assertion already names the client
    /// (FAPI 2 clients routinely omit it), so it is only compared when sent.
    /// </summary>
    private static bool IsSelfIssued(JsonWebToken token, string? clientId)
    {
        if (string.IsNullOrEmpty(token.Issuer)
            || !token.TryGetPayloadValue<string>(Claims.Subject, out var subject)
            || !string.Equals(subject, token.Issuer, StringComparison.Ordinal))
        {
            return false;
        }

        return string.IsNullOrEmpty(clientId)
            || string.Equals(clientId, subject, StringComparison.Ordinal);
    }
}

/// <summary>
/// Restores the internal token type of a client assertion accepted with a
/// standard <c>typ</c>. OpenIddict derives that type from the header, so a
/// <c>typ: JWT</c> assertion is taken for an ID token and refused right after
/// its signature was verified. Only a transaction marked by
/// <see cref="AcceptStandardClientAssertionType"/> is touched.
/// </summary>
internal sealed class RestoreStandardClientAssertionTokenType
    : IOpenIddictServerHandler<ValidateTokenContext>
{
    // OpenIddict compares this exact string; the constant it uses for it is
    // not part of the public abstractions (same situation as the device_code
    // literal in Tokens/DeviceCodeReplayGuard.cs).
    private const string ClientAssertionTokenType =
        "urn:openiddict:params:oauth:token-type:client_assertion";

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
            .UseSingletonHandler<RestoreStandardClientAssertionTokenType>()
            .SetOrder(Protection.ValidatePrincipal.Descriptor.Order - 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateTokenContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // The same transaction goes on to validate the authorization code or
        // the refresh token, so the mark is consumed here and the expected
        // type is checked as well: nothing else gets its type rewritten.
        if (context.Principal is { } principal
            && context.ValidTokenTypes.Contains(
                ClientAssertionTokenType,
                StringComparer.Ordinal)
            && context.Transaction.Properties.Remove(
                AcceptStandardClientAssertionType.RelaxedProperty))
        {
            principal.SetTokenType(ClientAssertionTokenType);
        }

        return default;
    }
}
