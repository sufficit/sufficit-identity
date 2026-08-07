using System.Text.Json;
using Microsoft.AspNetCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Sufficit.Identity.STS.Mtls;

internal sealed class AttachMtlsConfirmation(
    IMtlsClientCertificatePolicy certificatePolicy)
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
            .UseSingletonHandler<AttachMtlsConfirmation>()
            .SetOrder(PrepareUserCodePrincipal.Descriptor.Order + 600)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ProcessSignInContext context)
    {
        var httpContext = context.Transaction.GetHttpRequest()?.HttpContext;
        if (httpContext is null) return ValueTask.CompletedTask;
        var clientId = context.Transaction.Request?.ClientId
            ?? context.Principal?.GetClaim(Claims.ClientId);
        var decision = certificatePolicy.Evaluate(httpContext, clientId);
        if (!decision.Allowed || string.IsNullOrWhiteSpace(decision.Thumbprint))
            return ValueTask.CompletedTask;

        var confirmation = JsonSerializer.SerializeToElement(
            new Dictionary<string, string>
            {
                ["x5t#S256"] = Base64UrlEncoder.Encode(
                    Convert.FromHexString(decision.Thumbprint)),
            });
        context.AccessTokenPrincipal?.SetClaim(Claims.Confirmation, confirmation);
        if (context.IssuedTokenType is TokenTypeIdentifiers.AccessToken)
            context.IssuedTokenPrincipal?.SetClaim(Claims.Confirmation, confirmation);
        return ValueTask.CompletedTask;
    }
}
