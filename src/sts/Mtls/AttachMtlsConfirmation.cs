using OpenIddict.Abstractions;
using OpenIddict.Server;
using Sufficit.Identity.STS.Dpop;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Sufficit.Identity.STS.Mtls;

internal sealed class RejectCombinedDpopAndMtlsSenderConstraints
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
            .UseSingletonHandler<RejectCombinedDpopAndMtlsSenderConstraints>()
            .SetOrder(PrepareUserCodePrincipal.Descriptor.Order + 600)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ProcessSignInContext context)
    {
        if (context.Transaction.RemoteCertificate is not null
            && !string.IsNullOrWhiteSpace(context.Principal?.GetClaim(
                DpopProofValidator.BindingThumbprintClaimType)))
        {
            context.Reject(
                error: Errors.InvalidRequest,
                description:
                    "A token request cannot combine DPoP and mTLS sender constraints.");
            return ValueTask.CompletedTask;
        }
        return ValueTask.CompletedTask;
    }
}
