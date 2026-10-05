using System.Globalization;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Sufficit.Identity.STS.Grants;

/// <summary>
/// Names shared by the delegated-credential issuance, its refresh path and
/// the self-service surface. See <see cref="DelegatedCredentialOptions"/>.
/// </summary>
public static class DelegatedCredential
{
    /// <summary>RFC 9449 §10: thumbprint of the key the credential is bound to.</summary>
    public const string DpopJktParameter = "dpop_jkt";

    /// <summary>
    /// Caller-chosen device label (a UUID). Issuing again with the same label
    /// for the same user replaces the previous credential.
    /// </summary>
    public const string LabelParameter = "executor_id";

    /// <summary>
    /// Private request parameter holding the delegate audience, moved out of
    /// <c>audience</c> so OpenIddict's audience registry and per-client
    /// <c>aud:</c> permissions do not apply to a value that names a client.
    /// The leading dot keeps a client from supplying it directly (it is
    /// removed from every request first).
    /// </summary>
    internal const string AudienceParameter = ".delegated_credential_audience";

    /// <summary>
    /// Absolute deadline (Unix seconds) carried inside the credential's
    /// refresh tokens. Never emitted to an access or identity token.
    /// </summary>
    internal const string ExpiresAtClaimType = "dcred_exp";

    /// <summary>Device label carried inside the credential's refresh tokens.</summary>
    internal const string LabelClaimType = "dcred_label";

    /// <summary>
    /// OpenIddict authorization property recording the label, the delegating
    /// client and the absolute deadline: the self-service list and the
    /// per-user cap read it.
    /// </summary>
    public const string AuthorizationPropertyName = "delegated_credential";

    /// <summary>Whether a grant principal belongs to a delegated credential.</summary>
    public static bool IsDelegated(ClaimsPrincipal principal) =>
        !string.IsNullOrEmpty(principal.GetClaim(ExpiresAtClaimType));

    internal static DateTimeOffset? ExpiresAt(ClaimsPrincipal principal) =>
        long.TryParse(principal.GetClaim(ExpiresAtClaimType), NumberStyles.Integer,
            CultureInfo.InvariantCulture, out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;

    /// <summary>
    /// A canonical RFC 7638 SHA-256 thumbprint: 43 base64url characters
    /// without padding that decode to 32 bytes.
    /// </summary>
    public static bool IsValidThumbprint(string? value)
    {
        if (value is null || value.Length != 43
            || !value.All(character => char.IsAsciiLetterOrDigit(character)
                || character is '-' or '_'))
        {
            return false;
        }

        try
        {
            var bytes = Base64UrlEncoder.DecodeBytes(value);
            return bytes.Length == 32
                && string.Equals(Base64UrlEncoder.Encode(bytes), value, StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>Accepts a UUID and returns its canonical lowercase form.</summary>
    public static bool TryNormalizeLabel(string? value, out string label)
    {
        label = string.Empty;
        if (string.IsNullOrWhiteSpace(value)
            || !Guid.TryParse(value.Trim(), out var parsed)
            || parsed == Guid.Empty)
        {
            return false;
        }

        label = parsed.ToString("D");
        return true;
    }
}

/// <summary>
/// Moves the delegate client out of <c>audience</c> for a delegated-credential
/// request, before OpenIddict validates audiences (see
/// <see cref="DelegatedCredential.AudienceParameter"/>). Every other request
/// is left alone, so with the feature disabled nothing changes.
/// </summary>
internal sealed class DeferDelegatedCredentialAudience(TokenExchangeOptions options)
    : IOpenIddictServerHandler<ValidateTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
            .UseSingletonHandler<DeferDelegatedCredentialAudience>()
            .SetOrder(int.MinValue + 50_100)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateTokenRequestContext context)
    {
        var request = context.Request;
        request.RemoveParameter(DelegatedCredential.AudienceParameter);

        var delegation = options.DelegatedCredentials;
        if (!delegation.Enabled
            || !request.IsTokenExchangeGrantType()
            || !string.Equals(request.RequestedTokenType,
                TokenTypeIdentifiers.RefreshToken, StringComparison.Ordinal))
        {
            return ValueTask.CompletedTask;
        }

        var audiences = request.GetAudiences();
        if (audiences.Length == 1
            && string.Equals(audiences[0], delegation.DelegateClientId, StringComparison.Ordinal))
        {
            request.SetParameter(DelegatedCredential.AudienceParameter, audiences[0]);
            request.Audiences = null;
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Records the delegate client — not the delegating caller — as the
/// application of the refresh token a delegation issues, so the token store,
/// the self-service lists and revocation by application see the credential
/// under the client that actually uses it. The token exchange runs as the
/// caller, which is the client OpenIddict would otherwise record.
/// </summary>
internal sealed class AttachDelegatedCredentialApplication
    : IOpenIddictServerHandler<GenerateTokenContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
            .UseSingletonHandler<AttachDelegatedCredentialApplication>()
            .SetOrder(Protection.CreateTokenEntry.Descriptor.Order - 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(GenerateTokenContext context)
    {
        if (context.Principal is not { } principal
            || !string.Equals(context.TokenType, TokenTypeIdentifiers.RefreshToken, StringComparison.Ordinal)
            || !DelegatedCredential.IsDelegated(principal))
        {
            return ValueTask.CompletedTask;
        }

        var presenters = principal.GetPresenters();
        if (presenters.Length == 1)
        {
            context.ClientId = presenters[0];
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Keeps every token of a delegated credential inside its absolute deadline.
/// OpenIddict computes each refresh token's expiry from the moment it is
/// issued, so without this a credential refreshed regularly would never end.
/// Runs after OpenIddict prepares the token principals.
/// </summary>
internal sealed class ClampDelegatedCredentialLifetime
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
            .UseSingletonHandler<ClampDelegatedCredentialLifetime>()
            .SetOrder(PrepareUserCodePrincipal.Descriptor.Order + 600)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ProcessSignInContext context)
    {
        if (context.Principal is not { } principal
            || DelegatedCredential.ExpiresAt(principal) is not { } deadline)
        {
            return ValueTask.CompletedTask;
        }

        if (deadline <= context.Options.TimeProvider.GetUtcNow())
        {
            context.Reject(Errors.InvalidGrant, "The delegated credential has expired.");
            return ValueTask.CompletedTask;
        }

        foreach (var tokenPrincipal in new[]
        {
            context.AccessTokenPrincipal,
            context.RefreshTokenPrincipal,
            context.IssuedTokenPrincipal,
        })
        {
            if (tokenPrincipal is not null
                && (tokenPrincipal.GetExpirationDate() is not { } expiration || expiration > deadline))
            {
                tokenPrincipal.SetExpirationDate(deadline);
            }
        }

        return ValueTask.CompletedTask;
    }
}
