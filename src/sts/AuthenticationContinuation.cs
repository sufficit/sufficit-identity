using Microsoft.AspNetCore.WebUtilities;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS;

/// <summary>
/// Ends a credential form submission on a same-origin page before resuming an
/// OIDC authorization request as a separate browser navigation.
/// </summary>
internal static class AuthenticationContinuation
{
    internal const string Path = "/account/authenticationcontinue";

    internal static string Location(string? returnUrl) =>
        QueryHelpers.AddQueryString(
            Path,
            "returnUrl",
            LocalUrlValidator.EnsureLocal(returnUrl));
}
