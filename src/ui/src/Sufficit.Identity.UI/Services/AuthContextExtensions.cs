using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.UI.Services;

/// <summary>
/// Helpers to safely resolve the current authenticated <see cref="ApplicationUser"/>
/// from a Blazor <c>Task&lt;AuthenticationState&gt;</c> cascading parameter.
/// Centralizes the null/authenticated checks that every Manage page needs,
/// avoiding <see cref="NullReferenceException"/> when <c>_authTask</c> is null,
/// the user is not authenticated yet, or the principal has no matching Identity
/// user (e.g. during external login callback before cookie is set).
/// </summary>
public static class AuthContextExtensions
{
    /// <summary>
    /// Returns the authenticated <see cref="ApplicationUser"/>, or <c>null</c>
    /// when the auth state is unavailable, the request is unauthenticated, or
    /// the user no longer exists in the store. Never throws.
    /// </summary>
    public static async Task<ApplicationUser?> GetAuthenticatedUserAsync(
        this Task<AuthenticationState>? authTask,
        UserManager<ApplicationUser> userManager)
    {
        if (authTask is null) return null;

        var authState = await authTask;
        if (authState?.User?.Identity?.IsAuthenticated != true) return null;

        return await userManager.GetUserAsync(authState.User);
    }

    /// <summary>
    /// Returns the authenticated <see cref="ClaimsPrincipal"/>, or <c>null</c>
    /// when the auth state is unavailable or unauthenticated. Never throws.
    /// </summary>
    public static async Task<ClaimsPrincipal?> GetAuthenticatedPrincipalAsync(
        this Task<AuthenticationState>? authTask)
    {
        if (authTask is null) return null;
        var authState = await authTask;
        if (authState?.User?.Identity?.IsAuthenticated != true) return null;
        return authState.User;
    }
}
