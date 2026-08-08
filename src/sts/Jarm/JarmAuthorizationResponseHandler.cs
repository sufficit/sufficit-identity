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
    private readonly IJarmClientEncryptionCredentialsResolver _encryption;
    private readonly SufficitIdentityOptions _options;

    public JarmAuthorizationResponseHandler(
        JarmResponseGenerator generator,
        IJarmClientEncryptionCredentialsResolver encryption,
        SufficitIdentityOptions options)
    {
        _generator = generator;
        _encryption = encryption;
        _options = options;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor
            .CreateBuilder<ApplyAuthorizationResponseContext>()
            .UseScopedHandler<JarmAuthorizationResponseHandler>()
            // State and issuer must already be attached before they are moved
            // into the signed JWT. Host response writers execute later.
            .SetOrder(Authentication.AttachIssuer.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var requestedMode = context.ResponseMode;
        if (requestedMode is not (QueryJwt or FragmentJwt or FormPostJwt or Jwt))
        {
            return;
        }

        var clientId = context.Request?.ClientId;
        if (string.IsNullOrWhiteSpace(clientId) ||
            string.IsNullOrWhiteSpace(context.RedirectUri))
        {
            // Errors that cannot safely be redirected are deliberately left as
            // direct OpenIddict errors; there is no trusted audience/redirect
            // for a JARM response in that situation.
            return;
        }

        Microsoft.IdentityModel.Tokens.EncryptingCredentials? encryption = null;
        if (_options.Jarm.Encryption.Enabled)
        {
            encryption = await _encryption.ResolveAsync(clientId);
            if (encryption is null)
            {
                throw new InvalidOperationException(
                    $"JARM encryption is required, but client '{clientId}' has no eligible public encryption key in its registered JWKS.");
            }
        }

        var token = _generator.Generate(context.Response, clientId, encryption);
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

    }
}
