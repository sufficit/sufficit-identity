using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Sufficit.Identity.STS.Jarm;

/// <summary>
/// Replaces a normal authorization response with the single signed JARM
/// <c>response</c> parameter, then maps the JARM response mode to the matching
/// transport understood by the OpenIddict ASP.NET Core host integration.
/// </summary>
internal sealed class JarmAuthorizationResponseHandler :
    IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
{
    public const string QueryJwt = "query.jwt";
    public const string FragmentJwt = "fragment.jwt";
    public const string FormPostJwt = "form_post.jwt";
    public const string Jwt = "jwt";

    private readonly JarmResponseGenerator _generator;

    public JarmAuthorizationResponseHandler(JarmResponseGenerator generator) =>
        _generator = generator;

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor
            .CreateBuilder<ApplyAuthorizationResponseContext>()
            .UseSingletonHandler<JarmAuthorizationResponseHandler>()
            // State and issuer must already be attached before they are moved
            // into the signed JWT. Host response writers execute later.
            .SetOrder(Authentication.AttachIssuer.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var requestedMode = context.ResponseMode;
        if (requestedMode is not (QueryJwt or FragmentJwt or FormPostJwt or Jwt))
        {
            return ValueTask.CompletedTask;
        }

        var clientId = context.Request?.ClientId;
        if (string.IsNullOrWhiteSpace(clientId) ||
            string.IsNullOrWhiteSpace(context.RedirectUri))
        {
            // Errors that cannot safely be redirected are deliberately left as
            // direct OpenIddict errors; there is no trusted audience/redirect
            // for a JARM response in that situation.
            return ValueTask.CompletedTask;
        }

        var token = _generator.Generate(context.Response, clientId);
        foreach (var name in context.Response.GetParameters().Keys.ToArray())
        {
            context.Response.RemoveParameter(name);
        }
        context.Response.SetParameter("response", token);

        context.ResponseMode = requestedMode switch
        {
            FormPostJwt => OpenIddictConstants.ResponseModes.FormPost,
            FragmentJwt => OpenIddictConstants.ResponseModes.Fragment,
            // `jwt` uses the default transport for response_type=code, query.
            _ => OpenIddictConstants.ResponseModes.Query,
        };

        return ValueTask.CompletedTask;
    }
}
