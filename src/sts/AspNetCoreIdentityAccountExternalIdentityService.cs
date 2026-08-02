using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS;

/// <summary>
/// ASP.NET Identity adapter for external identities. The concrete name makes
/// the replaceable dependency explicit while the application contract remains
/// independent from this identity-store implementation.
/// </summary>
public sealed class AspNetCoreIdentityAccountExternalIdentityService(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    IHttpContextAccessor httpContextAccessor,
    ILogger<AspNetCoreIdentityAccountExternalIdentityService> logger)
    : IAccountExternalIdentityService
{
    private const string LastSignInMethodReason =
        "Adicione uma senha, passkey ou outra identidade antes de remover este acesso.";

    public async Task<AccountExternalIdentityOverview?> GetOverviewAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return null;
        }

        var logins = await userManager.GetLoginsAsync(user);
        cancellationToken.ThrowIfCancellationRequested();
        var canRemove = await HasAlternativeSignInMethodAsync(
            user,
            logins.Count,
            cancellationToken);
        var linkedProviders = logins
            .Select(login => login.LoginProvider)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var schemes = await signInManager
            .GetExternalAuthenticationSchemesAsync();
        cancellationToken.ThrowIfCancellationRequested();

        var linked = logins
            .Select(login => new AccountExternalIdentity(
                login.LoginProvider,
                login.ProviderKey,
                DisplayName(login.ProviderDisplayName, login.LoginProvider),
                canRemove,
                canRemove ? null : LastSignInMethodReason))
            .OrderBy(identity => identity.DisplayName, StringComparer.Ordinal)
            .ToArray();
        var available = schemes
            .Where(scheme => !linkedProviders.Contains(scheme.Name))
            .Select(scheme => new AccountExternalProvider(
                scheme.Name,
                DisplayName(scheme.DisplayName, scheme.Name)))
            .OrderBy(provider => provider.DisplayName, StringComparer.Ordinal)
            .ToArray();

        return new AccountExternalIdentityOverview(linked, available);
    }

    public async Task<AccountSelfServiceResult> LinkAsync(
        ClaimsPrincipal principal,
        AccountExternalIdentityLink command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return Unauthenticated();
        }

        var provider = command.LoginProvider?.Trim() ?? "";
        var providerKey = command.ProviderKey?.Trim() ?? "";
        if (provider.Length == 0 || providerKey.Length == 0)
        {
            return AccountSelfServiceResult.Failure(
                "external-identity-invalid",
                "A identidade externa recebida é inválida.");
        }

        var schemes = await signInManager
            .GetExternalAuthenticationSchemesAsync();
        var scheme = schemes.FirstOrDefault(candidate => string.Equals(
            candidate.Name,
            provider,
            StringComparison.OrdinalIgnoreCase));
        if (scheme is null)
        {
            return AccountSelfServiceResult.Failure(
                "external-provider-unavailable",
                "O provedor externo não está disponível.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        var owner = await userManager.FindByLoginAsync(
            scheme.Name,
            providerKey);
        if (owner is not null)
        {
            return owner.Id == user.Id
                ? AccountSelfServiceResult.Success
                : AccountSelfServiceResult.Failure(
                    "external-identity-in-use",
                    "Esta identidade externa já está vinculada a outra conta.");
        }

        var result = await userManager.AddLoginAsync(
            user,
            new UserLoginInfo(
                scheme.Name,
                providerKey,
                DisplayName(
                    command.ProviderDisplayName,
                    scheme.DisplayName ?? scheme.Name)));
        if (!result.Succeeded)
        {
            return FromIdentityResult(result);
        }

        await TryRefreshSignInAsync(user);
        logger.LogInformation(
            "User {UserId} linked external identity provider {Provider}.",
            user.Id,
            scheme.Name);
        return AccountSelfServiceResult.Success;
    }

    public async Task<AccountSelfServiceResult> RemoveAsync(
        ClaimsPrincipal principal,
        string loginProvider,
        string providerKey,
        CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return Unauthenticated();
        }

        loginProvider = loginProvider?.Trim() ?? "";
        providerKey = providerKey?.Trim() ?? "";
        var logins = await userManager.GetLoginsAsync(user);
        var login = logins.FirstOrDefault(candidate =>
            string.Equals(
                candidate.LoginProvider,
                loginProvider,
                StringComparison.Ordinal)
            && string.Equals(
                candidate.ProviderKey,
                providerKey,
                StringComparison.Ordinal));
        if (login is null)
        {
            return AccountSelfServiceResult.Failure(
                "external-identity-not-found",
                "A identidade externa não foi encontrada.");
        }

        if (!await HasAlternativeSignInMethodAsync(
                user,
                logins.Count,
                cancellationToken))
        {
            return AccountSelfServiceResult.Failure(
                "last-sign-in-method",
                LastSignInMethodReason);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var result = await userManager.RemoveLoginAsync(
            user,
            login.LoginProvider,
            login.ProviderKey);
        if (!result.Succeeded)
        {
            return FromIdentityResult(result);
        }

        await TryRefreshSignInAsync(user);
        logger.LogInformation(
            "User {UserId} removed external identity provider {Provider}.",
            user.Id,
            login.LoginProvider);
        return AccountSelfServiceResult.Success;
    }

    private async Task<bool> HasAlternativeSignInMethodAsync(
        ApplicationUser user,
        int linkedIdentityCount,
        CancellationToken cancellationToken)
    {
        if (linkedIdentityCount > 1
            || await userManager.HasPasswordAsync(user))
        {
            return true;
        }

        cancellationToken.ThrowIfCancellationRequested();
        var passkeys = await userManager.GetPasskeysAsync(user);
        cancellationToken.ThrowIfCancellationRequested();
        return passkeys.Count > 0;
    }

    private async Task<ApplicationUser?> GetAuthenticatedUserAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        cancellationToken.ThrowIfCancellationRequested();
        if (principal.Identity?.IsAuthenticated != true)
        {
            return null;
        }

        var user = await userManager.GetUserAsync(principal);
        cancellationToken.ThrowIfCancellationRequested();
        return user;
    }

    private async Task TryRefreshSignInAsync(ApplicationUser user)
    {
        if (httpContextAccessor.HttpContext is null)
        {
            return;
        }

        try
        {
            await signInManager.RefreshSignInAsync(user);
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                exception,
                "The interactive session could not be refreshed after changing external identities for user {UserId}.",
                user.Id);
        }
    }

    private static string DisplayName(string? value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value;

    private static AccountSelfServiceResult FromIdentityResult(
        IdentityResult result) =>
        new(
            result.Succeeded,
            result.Errors
                .Select(error => new AccountSelfServiceError(
                    error.Code,
                    error.Description))
                .ToArray());

    private static AccountSelfServiceResult Unauthenticated() =>
        AccountSelfServiceResult.Failure(
            "unauthenticated",
            "A sessão não está autenticada.");
}
