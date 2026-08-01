using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace Sufficit.Identity.UI.Services;

/// <summary>
/// Presentation helper for resolving the authenticated principal from Blazor
/// authentication state without accessing an identity store.
/// </summary>
public static class AuthContextExtensions
{
    public static async Task<ClaimsPrincipal?> GetAuthenticatedPrincipalAsync(
        this Task<AuthenticationState>? authenticationStateTask)
    {
        if (authenticationStateTask is null)
            return null;

        var authenticationState = await authenticationStateTask;
        return authenticationState?.User?.Identity?.IsAuthenticated == true
            ? authenticationState.User
            : null;
    }
}
