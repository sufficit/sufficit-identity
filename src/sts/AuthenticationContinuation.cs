using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.Http;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS;

/// <summary>
/// Ends a credential form submission on a same-origin page before resuming an
/// OIDC authorization request as a separate browser navigation.
/// </summary>
internal static class AuthenticationContinuation
{
    internal const string Path = "/account/authenticationcontinue";

    internal static string Location(string? returnUrl, HttpContext? context = null)
    {
        if (context is not null)
            AuthorizationAuthenticationReceipt.Issue(context, LocalUrlValidator.EnsureLocal(returnUrl));
        return QueryHelpers.AddQueryString(
            Path,
            "returnUrl",
            LocalUrlValidator.EnsureLocal(returnUrl));
    }
}
