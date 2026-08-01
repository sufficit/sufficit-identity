using Microsoft.AspNetCore;     // GetOpenIddictServerRequest() extension lives here
using Microsoft.AspNetCore.Http;
using OpenIddict.Abstractions;

namespace Sufficit.Identity.UI.Services;

/// <summary>
/// Reads the OpenIddict request attached to the current HTTP transaction.
/// Used by Blazor components to access <c>client_id</c>, requested scopes,
/// <c>prompt</c>, <c>redirect_uri</c>, etc. of a pending
/// <c>/connect/authorize</c> or device flow request.
/// </summary>
public interface IOpenIddictRequestAccessor
{
    /// <summary>The OpenIddict request for the current HTTP context, or null.</summary>
    OpenIddictRequest? GetCurrentRequest();
}

internal sealed class OpenIddictRequestAccessor : IOpenIddictRequestAccessor
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public OpenIddictRequestAccessor(IHttpContextAccessor httpContextAccessor)
        => _httpContextAccessor = httpContextAccessor;

    public OpenIddictRequest? GetCurrentRequest()
        => _httpContextAccessor.HttpContext?.GetOpenIddictServerRequest();
}
