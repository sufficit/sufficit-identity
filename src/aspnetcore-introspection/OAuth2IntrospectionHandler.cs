using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Sufficit.Identity.AspNetCore.Authentication.OAuth2Introspection;

/// <summary>
/// Authenticates reference tokens by introspection. Refusals produce 401 with <c>WWW-Authenticate</c>;
/// an unavailable introspection endpoint produces 503, so clients retry instead of discarding a valid token.
/// </summary>
public sealed class OAuth2IntrospectionHandler(IOptionsMonitor<OAuth2IntrospectionOptions> options, ILoggerFactory logger,
    UrlEncoder encoder, IOAuth2IntrospectionClient introspection)
    : AuthenticationHandler<OAuth2IntrospectionOptions>(options, logger, encoder)
{
    private new OAuth2IntrospectionEvents Events => (OAuth2IntrospectionEvents)base.Events!;

    protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new OAuth2IntrospectionEvents());

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var token = Options.TokenRetriever(Request);
        if (string.IsNullOrEmpty(token)) return AuthenticateResult.NoResult();
        try
        {
            var result = await introspection.IntrospectAsync(token, Options, Context.RequestAborted);
            if (!result.IsActive) return await FailAsync(new UnauthorizedAccessException("Token is not active."));
            if (result.ExpiresAt is { } exp && exp <= TimeProvider.GetUtcNow())
                return await FailAsync(new UnauthorizedAccessException("Token is expired."));

            var identity = new ClaimsIdentity(result.ToClaims(ClaimsIssuer ?? Options.ResolveEndpoint()),
                Options.AuthenticationType ?? Scheme.Name, Options.NameClaimType, Options.RoleClaimType);
            var properties = new AuthenticationProperties();
            if (Options.SaveToken) properties.StoreTokens([new AuthenticationToken { Name = "access_token", Value = token }]);
            var validated = new TokenValidatedContext(Context, Scheme, Options, result)
            {
                Principal = new ClaimsPrincipal(identity),
                Properties = properties,
            };
            await Events.TokenValidated(validated);
            if (validated.Result is not null) return validated.Result;
            validated.Success();
            return validated.Result!;
        }
        catch (IntrospectionUnavailableException ex)
        {
            Context.Items[OAuth2IntrospectionDefaults.UnavailableItemKey] = ex;
            return await FailAsync(ex);
        }
    }

    private async Task<AuthenticateResult> FailAsync(Exception error)
    {
        var failed = new AuthenticationFailedContext(Context, Scheme, Options, error);
        await Events.AuthenticationFailed(failed);
        return failed.Result ?? AuthenticateResult.Fail(error);
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (Context.Items.ContainsKey(OAuth2IntrospectionDefaults.UnavailableItemKey))
        {
            Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            Response.Headers.RetryAfter = "5";
            return Task.CompletedTask;
        }
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.Append("WWW-Authenticate", Options.TokenRetriever(Request) is null
            ? "Bearer" : "Bearer error=\"invalid_token\"");
        return Task.CompletedTask;
    }
}
