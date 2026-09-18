using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Sufficit.Identity.STS.Grants;

/// <summary>
/// Answers a token request that omits <c>code_verifier</c> with
/// <c>invalid_grant</c> when the client had to use PKCE.
/// </summary>
/// <remarks>
/// RFC 7636 section 4.6 states the verifier is compared with the stored
/// challenge and a mismatch is <c>invalid_grant</c>; a request with no verifier
/// at all cannot match either, which is how the OpenID conformance suite reads
/// it (<c>fapi2-...-ensure-pkce-code-verifier-required</c>). OpenIddict reports
/// the missing parameter as <c>invalid_request</c> before the code is read, so
/// the decision is taken here, from what the client was required to do: a
/// client that never uses PKCE keeps the built-in behavior untouched.
/// </remarks>
internal sealed class RejectMissingCodeVerifier(
    IOpenIddictApplicationManager applications,
    SufficitIdentityOptions options)
    : IOpenIddictServerHandler<ValidateTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor
            .CreateBuilder<ValidateTokenRequestContext>()
            .UseScopedHandler<RejectMissingCodeVerifier>()
            // Before both of OpenIddict's PKCE handlers: the requirement one
            // reports the missing parameter as invalid_request (ID2029).
            .SetOrder(Math.Min(
                Exchange.ValidateProofKeyForCodeExchangeRequirement.Descriptor.Order,
                Exchange.ValidateProofKeyForCodeExchangeParameters.Descriptor.Order) - 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidateTokenRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.Request.IsAuthorizationCodeGrantType()
            || !string.IsNullOrEmpty(context.Request.CodeVerifier))
        {
            return;
        }

        if (!await RequiresProofKeyAsync(context))
        {
            return;
        }

        context.Reject(
            error: Errors.InvalidGrant,
            description: "The code_verifier of the authorization code is missing.");
    }

    private async ValueTask<bool> RequiresProofKeyAsync(
        ValidateTokenRequestContext context)
    {
        if (options.Pkce.RequireForAllClients)
        {
            return true;
        }

        if (string.IsNullOrEmpty(context.Request.ClientId))
        {
            return false;
        }

        var application = await applications.FindByClientIdAsync(
            context.Request.ClientId,
            context.CancellationToken);

        return application is not null
            && await applications.HasRequirementAsync(
                application,
                Requirements.Features.ProofKeyForCodeExchange,
                context.CancellationToken);
    }
}
