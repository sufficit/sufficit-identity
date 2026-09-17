using Microsoft.AspNetCore;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Sufficit.Identity.STS.Dpop;

/// <summary>
/// <para>
/// Binds a pushed authorization request to the DPoP key proven in the
/// <c>DPoP</c> header (RFC 9449, section 10.1). The client can name the key
/// with the <c>dpop_jkt</c> parameter, but it may also simply send a proof with
/// the PAR request — the authorization server then takes the thumbprint from
/// the proof it just verified, which is the stronger of the two and what the
/// OpenID conformance suite's FAPI 2 plan does.
/// </para>
/// <para>
/// Without this, a PAR request carrying a proof and no <c>dpop_jkt</c> was
/// refused by the FAPI 2 profile check ("a valid dpop_jkt parameter is
/// required to bind the authorization code") even though the client had proven
/// possession of the key.
/// </para>
/// </summary>
internal sealed class BindPushedAuthorizationToDpopProof(
    DpopProofValidator validator)
    : IOpenIddictServerHandler<ValidatePushedAuthorizationRequestContext>
{
    public const string DpopKeyThumbprintParameter = "dpop_jkt";

    // RFC 9449 section 7.1; OpenIddict's Errors constants do not include it.
    private const string InvalidDpopProof = "invalid_dpop_proof";

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor
            .CreateBuilder<ValidatePushedAuthorizationRequestContext>()
            // Before the FAPI 2 profile check, which reads dpop_jkt.
            .UseScopedHandler<BindPushedAuthorizationToDpopProof>()
            .SetOrder(Authentication.ValidatePushedAuthorizedParty.Descriptor.Order + 250)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidatePushedAuthorizationRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var request = context.Transaction.GetHttpRequest();
        var header = request?.Headers["DPoP"].ToString();
        if (string.IsNullOrEmpty(header))
        {
            // No proof: dpop_jkt alone still binds the code, and a client that
            // uses neither is only rejected where a profile requires it.
            return;
        }

        var proof = await validator.ValidateAsync(
            header,
            request!.Method,
            request.Scheme + "://" + request.Host + request.PathBase + request.Path,
            expectedNonce: null,
            context.CancellationToken);

        if (proof is null)
        {
            context.Reject(
                error: InvalidDpopProof,
                description: "The DPoP proof sent with the pushed authorization request is not valid.");
            return;
        }

        var declared = (string?)context.Request[DpopKeyThumbprintParameter];
        if (!string.IsNullOrEmpty(declared)
            && !string.Equals(declared, proof.KeyThumbprint, StringComparison.Ordinal))
        {
            context.Reject(
                error: InvalidDpopProof,
                description: "The dpop_jkt parameter does not match the key of the DPoP proof.");
            return;
        }

        // Stored with the request: /connect/authorize restores it from the
        // request_uri and the authorization code is bound to this key.
        context.Request[DpopKeyThumbprintParameter] = proof.KeyThumbprint;
    }
}
