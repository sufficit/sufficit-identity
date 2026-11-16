using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Sufficit.Identity.AspNetCore.Authentication.OAuth2Introspection;

/// <summary>Callbacks of the handler (subset of Duende's events).</summary>
public class OAuth2IntrospectionEvents
{
    public Func<TokenValidatedContext, Task> OnTokenValidated { get; set; } = _ => Task.CompletedTask;
    public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = _ => Task.CompletedTask;

    public virtual Task TokenValidated(TokenValidatedContext context) => OnTokenValidated(context);
    public virtual Task AuthenticationFailed(AuthenticationFailedContext context) => OnAuthenticationFailed(context);
}

/// <summary>Raised after an active token became a principal; may replace or reject it.</summary>
public sealed class TokenValidatedContext(HttpContext context, AuthenticationScheme scheme, OAuth2IntrospectionOptions options,
    IntrospectionResult introspection) : ResultContext<OAuth2IntrospectionOptions>(context, scheme, options)
{
    public IntrospectionResult Introspection { get; } = introspection;
}

/// <summary>Raised when the token is refused or the introspection endpoint is unavailable.</summary>
public sealed class AuthenticationFailedContext(HttpContext context, AuthenticationScheme scheme, OAuth2IntrospectionOptions options,
    Exception error) : ResultContext<OAuth2IntrospectionOptions>(context, scheme, options)
{
    public Exception Error { get; } = error;
}
