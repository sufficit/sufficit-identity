using Microsoft.AspNetCore;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Sufficit.Identity.Application.Security;
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

        var httpContext = context.Transaction.GetHttpRequest()?.HttpContext;
        var response = httpContext?.Response;
        if (response is null)
        {
            return ValueTask.CompletedTask;
        }

        var header = options.Csp.ReportOnly
            ? "Content-Security-Policy-Report-Only"
            : "Content-Security-Policy";
        // This handler REPLACES the header the security-headers middleware
        // already emitted, so it has to carry the request's nonce forward.
        // Rebuilding without it silently put 'unsafe-inline' back on style-src
        // for exactly the form-post authorization response — the one page in
        // the flow that renders an auto-submitting form.
        response.Headers[header] = SecurityHeadersMiddlewareExtensions
            .BuildFormPostContentSecurityPolicy(
                options,
                context.RedirectUri,
                CspNonce.From(httpContext!.Items));

        return ValueTask.CompletedTask;
    }
}
