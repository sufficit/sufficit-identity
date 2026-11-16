using System.Net;

namespace Sufficit.Identity.AspNetCore.Authentication.OAuth2Introspection;

/// <summary>
/// The introspection endpoint could not give a verdict (network error, timeout, 5xx, 429, or any
/// non-2xx answer). It says nothing about the token, so the handler answers 503, never 401.
/// </summary>
public sealed class IntrospectionUnavailableException(string message, HttpStatusCode? statusCode = null, Exception? inner = null)
    : Exception(message, inner)
{
    /// <summary>Status returned by the endpoint, when it answered at all.</summary>
    public HttpStatusCode? StatusCode { get; } = statusCode;
}
