using OpenIddict.Abstractions;
using OpenIddict.Server;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Services;

namespace Sufficit.Identity.STS.Tokens;

/// <summary>Recovery sessions cannot mint OAuth credentials until TOTP is re-enrolled.</summary>
internal sealed class MfaRecoveryTokenGuard(AppDbContext database)
    : IOpenIddictServerHandler<OpenIddictServerEvents.GenerateTokenContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<OpenIddictServerEvents.GenerateTokenContext>()
            .UseScopedHandler<MfaRecoveryTokenGuard>()
            .SetOrder(int.MinValue + 90_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(OpenIddictServerEvents.GenerateTokenContext context)
    {
        var subject = context.Principal?.GetClaim(OpenIddictConstants.Claims.Subject);
        if (!string.IsNullOrWhiteSpace(subject)
            && await MfaRecoveryState.IsRequiredAsync(database, subject, context.CancellationToken))
        {
            context.Reject(OpenIddictConstants.Errors.AccessDenied,
                "Configure two-factor authentication again at /manage/twofactor before continuing.");
        }
    }
}
