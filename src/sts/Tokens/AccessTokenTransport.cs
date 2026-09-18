using Microsoft.AspNetCore;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Sufficit.Identity.STS.Tokens;

/// <summary>
/// Refuses an access token presented in the query string of a UserInfo
/// request. RFC 6750 section 2.3 discourages that transport — the URL ends up
/// in proxy logs, browser history and the Referer header — and FAPI 2.0
/// forbids it (conformance: <c>DisallowAccessTokenInQuery</c>). A deployment
/// still migrating a legacy consumer can allow it again with
/// <c>Sufficit:Identity:Tokens:AllowAccessTokenInQueryString</c>.
/// </summary>
internal sealed class RejectAccessTokenInQueryString(
    SufficitIdentityOptions options)
    : IOpenIddictServerHandler<ExtractUserInfoRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor
            .CreateBuilder<ExtractUserInfoRequestContext>()
            .UseScopedHandler<RejectAccessTokenInQueryString>()
            .SetOrder(
                OpenIddictServerAspNetCoreHandlers
                    .ExtractAccessToken<ExtractUserInfoRequestContext>
                    .Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ExtractUserInfoRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (options.Tokens.AllowAccessTokenInQueryString)
        {
            return default;
        }

        var request = context.Transaction.GetHttpRequest();
        if (request is not null
            && request.Query.ContainsKey(Parameters.AccessToken))
        {
            context.Reject(
                error: Errors.InvalidRequest,
                description: "The access token must be sent in the Authorization header.");
        }

        return default;
    }
}
