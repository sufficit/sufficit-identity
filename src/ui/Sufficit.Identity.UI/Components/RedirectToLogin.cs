using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.WebUtilities;

namespace Sufficit.Identity.UI.Components;

/// <summary>
/// Redirects unauthenticated users to /Account/Login, preserving the
/// current URL as <c>ReturnUrl</c>.
/// </summary>
internal sealed class RedirectToLogin : ComponentBase
{
    [Inject] public required NavigationManager Navigation { get; set; }
    [CascadingParameter] public required Task<AuthenticationState> AuthState { get; set; }

    protected override void OnInitialized()
    {
        var user = AuthState.GetAwaiter().GetResult().User;
        if (user.Identity?.IsAuthenticated != true)
        {
            var returnUrl = Navigation.ToBaseRelativePath(Navigation.Uri);
            var query = new Dictionary<string, string?> { ["returnUrl"] = "/" + returnUrl };
            var loginUrl = QueryHelpers.AddQueryString("/account/login", query);
            Navigation.NavigateTo(loginUrl, forceLoad: true);
        }
    }
}
