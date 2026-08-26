using Microsoft.AspNetCore;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Sufficit.Identity.STS.Security;

/// <summary>
/// Tailors CSP for OpenID Connect <c>response_mode=form_post</c> after the
/// redirect URI has been validated. This keeps CSP enforceable without a
/// global <c>'unsafe-inline'</c> exception or duplicated client allow-lists.
/// </summary>
internal sealed class AttachFormPostContentSecurityPolicy(
    SufficitIdentityOptions options)
    : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor
            .CreateBuilder<ApplyAuthorizationResponseContext>()
            .UseSingletonHandler<AttachFormPostContentSecurityPolicy>()
            .SetOrder(OpenIddict.Server.AspNetCore
                .OpenIddictServerAspNetCoreHandlers.Authentication
                .ProcessFormPostResponse.Descriptor.Order - 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!options.Csp.Enabled
            || !string.Equals(
                context.ResponseMode,
                OpenIddictConstants.ResponseModes.FormPost,
                StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(context.RedirectUri))
        {
            return ValueTask.CompletedTask;
        }

        var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
        if (response is null)
        {
            return ValueTask.CompletedTask;
        }

        var header = options.Csp.ReportOnly
            ? "Content-Security-Policy-Report-Only"
            : "Content-Security-Policy";
        response.Headers[header] = SecurityHeadersMiddlewareExtensions
            .BuildFormPostContentSecurityPolicy(options, context.RedirectUri);

        return ValueTask.CompletedTask;
    }
}
