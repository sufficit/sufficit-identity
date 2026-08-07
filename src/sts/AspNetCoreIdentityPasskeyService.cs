using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// ASP.NET Identity adapter for WebAuthn registration and authentication.
/// Passkey challenge state remains in the framework's protected temporary
/// authentication ticket, backed by the runtime ticket store, and therefore
/// challenge-producing/consuming calls must run inside ordinary HTTP requests.
/// </summary>
public sealed class AspNetCoreIdentityPasskeyService(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    ISecurityEventTrigger securityEvents,
    ICredentialMutationSecurityCoordinator credentialSecurity,
    AccountPasskeyOptions options,
    ILogger<AspNetCoreIdentityPasskeyService> logger)
    : IAccountPasskeyService, IPasskeyAuthenticationService
{
    public async Task<AccountPasskeyOverview?> GetOverviewAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        return user is null
            ? null
            : await BuildOverviewAsync(user, cancellationToken);
    }

    public async Task<PasskeyOptionsResult> CreateRegistrationOptionsAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return PasskeyOptionsResult.Failure(
                "unauthenticated",
                "A sessão não está autenticada.");
        }

        var authorization = await credentialSecurity.AuthorizeAsync(
            principal,
            "passkey-registration",
            cancellationToken: cancellationToken);
        if (!authorization.Allowed)
        {
            return PasskeyOptionsResult.Failure(
                authorization.ErrorCode!,
                authorization.ErrorDescription!);
        }

        var overview = await BuildOverviewAsync(user, cancellationToken);
        if (!overview.CanRegister)
        {
            return PasskeyOptionsResult.Failure(
                "passkey-limit-reached",
                $"Esta conta já possui o limite de {overview.MaximumCredentials} passkeys.");
        }

        var accountName = await userManager.GetUserNameAsync(user)
            ?? await userManager.GetEmailAsync(user)
            ?? user.Id;
        cancellationToken.ThrowIfCancellationRequested();
        var optionsJson = await signInManager.MakePasskeyCreationOptionsAsync(
            new PasskeyUserEntity
            {
                Id = user.Id,
                Name = accountName,
                DisplayName = accountName,
            });
        cancellationToken.ThrowIfCancellationRequested();
        return PasskeyOptionsResult.Success(optionsJson);
    }

    public async Task<AccountPasskeyResult> RegisterAsync(
        ClaimsPrincipal principal,
        AccountPasskeyRegistration command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return AccountPasskeyResult.Failure(
                "unauthenticated",
                "A sessão não está autenticada.");
        }

        var authorization = await credentialSecurity.AuthorizeAsync(
            principal,
            "passkey-registration",
            cancellationToken: cancellationToken);
        if (!authorization.Allowed)
        {
            return AccountPasskeyResult.Failure(
                authorization.ErrorCode!,
                authorization.ErrorDescription!,
                await BuildOverviewAsync(user, cancellationToken));
        }

        var overview = await BuildOverviewAsync(user, cancellationToken);
        if (!overview.CanRegister)
        {
            return AccountPasskeyResult.Failure(
                "passkey-limit-reached",
                $"Esta conta já possui o limite de {overview.MaximumCredentials} passkeys.",
                overview);
        }

        var credentialJson = command.CredentialJson?.Trim() ?? "";
        if (credentialJson.Length == 0)
        {
            return AccountPasskeyResult.Failure(
                "passkey-credential-required",
                "O navegador não forneceu a credencial da passkey.",
                overview);
        }

        if (Encoding.UTF8.GetByteCount(credentialJson) > MaximumCredentialPayloadBytes)
        {
            return AccountPasskeyResult.Failure(
                "passkey-credential-too-large",
                "A credencial recebida excede o tamanho permitido.",
                overview);
        }

        var name = command.Name?.Trim();
        if (name?.Length > MaximumNameLength)
        {
            return AccountPasskeyResult.Failure(
                "passkey-name-too-long",
                $"O nome deve ter no máximo {MaximumNameLength} caracteres.",
                overview);
        }

        PasskeyAttestationResult attestation;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            attestation = await signInManager.PerformPasskeyAttestationAsync(
                credentialJson);
        }
        catch (Exception exception) when (IsInvalidCeremony(exception))
        {
            logger.LogWarning(
                exception,
                "Passkey registration ceremony was invalid for user {UserId}.",
                user.Id);
            return AccountPasskeyResult.Failure(
                "passkey-ceremony-invalid",
                "A solicitação de registro expirou ou é inválida. Inicie novamente.",
                overview);
        }

        if (!attestation.Succeeded || attestation.Passkey is null)
        {
            logger.LogWarning(
                "Passkey attestation failed for user {UserId}: {Reason}",
                user.Id,
                attestation.Failure?.Message ?? "unspecified");
            return AccountPasskeyResult.Failure(
                "passkey-attestation-failed",
                "A passkey não pôde ser validada. Tente registrá-la novamente.",
                overview);
        }

        attestation.Passkey.Name = string.IsNullOrWhiteSpace(name)
            ? null
            : name;
        var stored = await userManager.AddOrUpdatePasskeyAsync(
            user,
            attestation.Passkey);
        if (!stored.Succeeded)
        {
            return FromIdentityResult(
                stored,
                await BuildOverviewAsync(user, cancellationToken));
        }

        var state = await BuildOverviewAsync(user, cancellationToken);
        logger.LogInformation(
            "User {UserId} registered passkey {CredentialId}.",
            user.Id,
            WebEncoders.Base64UrlEncode(attestation.Passkey.CredentialId));

        var credentialIdB64 = WebEncoders.Base64UrlEncode(attestation.Passkey.CredentialId);
        await securityEvents.DeviceChangedAsync(
            principal,
            user.Id,
            new CaepDeviceChange(CaepChangeOperation.Created, credentialIdB64, attestation.Passkey.Name),
            cancellationToken);
        await credentialSecurity.CompleteAsync(
            user,
            principal,
            new CaepCredentialChange(
                CaepCredentialType.Passkey,
                CaepChangeOperation.Created),
            cancellationToken);

        return AccountPasskeyResult.Success(state);
    }

    public async Task<AccountPasskeyResult> RenameAsync(
        ClaimsPrincipal principal,
        AccountPasskeyRename command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return AccountPasskeyResult.Failure(
                "unauthenticated",
                "A sessão não está autenticada.");
        }
        var credentialId = command.CredentialId?.Trim() ?? "";
        if (credentialId.Length == 0)
        {
            return AccountPasskeyResult.Failure(
                "passkey-credential-required",
                "A passkey que será renomeada não foi informada.",
                await BuildOverviewAsync(user, cancellationToken));
        }

        var name = command.Name?.Trim();
        if (name?.Length > MaximumNameLength)
        {
            return AccountPasskeyResult.Failure(
                "passkey-name-too-long",
                $"O nome deve ter no máximo {MaximumNameLength} caracteres.",
                await BuildOverviewAsync(user, cancellationToken));
        }

        var passkeys = await userManager.GetPasskeysAsync(user);
        cancellationToken.ThrowIfCancellationRequested();
        var passkey = passkeys.FirstOrDefault(candidate => string.Equals(
            WebEncoders.Base64UrlEncode(candidate.CredentialId),
            credentialId,
            StringComparison.Ordinal));
        if (passkey is null)
        {
            return AccountPasskeyResult.Failure(
                "passkey-not-found",
                "A passkey não foi encontrada.",
                await BuildOverviewAsync(user, cancellationToken));
        }

        passkey.Name = string.IsNullOrWhiteSpace(name) ? null : name;
        var renamed = await userManager.AddOrUpdatePasskeyAsync(user, passkey);
        var state = await BuildOverviewAsync(user, cancellationToken);
        if (!renamed.Succeeded)
        {
            return FromIdentityResult(renamed, state);
        }

        logger.LogInformation(
            "User {UserId} renamed passkey {CredentialId}.",
            user.Id,
            credentialId);
        return AccountPasskeyResult.Success(state);
    }

    public async Task<AccountPasskeyResult> RemoveAsync(
        ClaimsPrincipal principal,
        string credentialId,
        CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return AccountPasskeyResult.Failure(
                "unauthenticated",
                "A sessão não está autenticada.");
        }

        var authorization = await credentialSecurity.AuthorizeAsync(
            principal,
            "passkey-removal",
            cancellationToken: cancellationToken);
        if (!authorization.Allowed)
        {
            return AccountPasskeyResult.Failure(
                authorization.ErrorCode!,
                authorization.ErrorDescription!,
                await BuildOverviewAsync(user, cancellationToken));
        }

        var passkeys = await userManager.GetPasskeysAsync(user);
        cancellationToken.ThrowIfCancellationRequested();
        var passkey = passkeys.FirstOrDefault(candidate => string.Equals(
            WebEncoders.Base64UrlEncode(candidate.CredentialId),
            credentialId,
            StringComparison.Ordinal));
        if (passkey is null)
        {
            return AccountPasskeyResult.Failure(
                "passkey-not-found",
                "A passkey não foi encontrada.",
                await BuildOverviewAsync(user, cancellationToken));
        }

        var removed = await userManager.RemovePasskeyAsync(
            user,
            passkey.CredentialId);
        var state = await BuildOverviewAsync(user, cancellationToken);
        if (!removed.Succeeded)
        {
            return FromIdentityResult(removed, state);
        }

        logger.LogInformation(
            "User {UserId} removed passkey {CredentialId}.",
            user.Id,
            credentialId);

        await securityEvents.DeviceChangedAsync(
            principal,
            user.Id,
            new CaepDeviceChange(CaepChangeOperation.Deleted, credentialId, passkey.Name),
            cancellationToken);
        await credentialSecurity.CompleteAsync(
            user,
            principal,
            new CaepCredentialChange(
                CaepCredentialType.Passkey,
                CaepChangeOperation.Deleted),
            cancellationToken);

        return AccountPasskeyResult.Success(state);
    }

    public async Task<PasskeyOptionsResult> CreateRequestOptionsAsync(
        string? username,
        CancellationToken cancellationToken = default)
    {
        username = username?.Trim();
        if (username?.Length > MaximumUsernameLength)
        {
            return PasskeyOptionsResult.Failure(
                "username-too-long",
                "O identificador da conta excede o tamanho permitido.");
        }

        ApplicationUser? user = null;
        if (!string.IsNullOrWhiteSpace(username))
        {
            user = await userManager.FindByNameAsync(username)
                ?? await userManager.FindByEmailAsync(username);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var optionsJson = await signInManager.MakePasskeyRequestOptionsAsync(user);
        cancellationToken.ThrowIfCancellationRequested();
        return PasskeyOptionsResult.Success(optionsJson);
    }

    public async Task<PasskeyAuthenticationResult> SignInAsync(
        string? credentialJson,
        CancellationToken cancellationToken = default)
    {
        credentialJson = credentialJson?.Trim();
        if (string.IsNullOrEmpty(credentialJson))
        {
            return PasskeyAuthenticationResult.Failure(
                "passkey-credential-required",
                "O navegador não forneceu uma passkey.");
        }

        if (Encoding.UTF8.GetByteCount(credentialJson) > MaximumCredentialPayloadBytes)
        {
            return PasskeyAuthenticationResult.Failure(
                "passkey-credential-too-large",
                "A credencial recebida excede o tamanho permitido.");
        }

        SignInResult result;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            result = await signInManager.PasskeySignInAsync(credentialJson);
        }
        catch (Exception exception) when (IsInvalidCeremony(exception))
        {
            logger.LogWarning(
                exception,
                "Passkey authentication ceremony was invalid.");
            return PasskeyAuthenticationResult.Failure(
                "passkey-ceremony-invalid",
                "A solicitação de autenticação expirou ou é inválida. Tente novamente.");
        }

        if (result.Succeeded)
        {
            logger.LogInformation("A user signed in with a passkey.");
            return PasskeyAuthenticationResult.Success;
        }

        if (result.IsLockedOut)
        {
            return PasskeyAuthenticationResult.Failure(
                "account-locked",
                "A conta está temporariamente bloqueada.");
        }

        if (result.IsNotAllowed)
        {
            return PasskeyAuthenticationResult.Failure(
                "sign-in-not-allowed",
                "O login não está permitido para esta conta.");
        }

        return PasskeyAuthenticationResult.Failure(
            "passkey-authentication-failed",
            "A passkey não pôde ser autenticada.");
    }

    private async Task<AccountPasskeyOverview> BuildOverviewAsync(
        ApplicationUser user,
        CancellationToken cancellationToken)
    {
        var passkeys = await userManager.GetPasskeysAsync(user);
        cancellationToken.ThrowIfCancellationRequested();
        var maximum = MaximumCredentials;
        var credentials = passkeys
            .Select(passkey => new AccountPasskeyCredential(
                WebEncoders.Base64UrlEncode(passkey.CredentialId),
                passkey.Name,
                passkey.CreatedAt,
                passkey.IsBackedUp,
                passkey.IsBackupEligible))
            .OrderByDescending(passkey => passkey.CreatedAt)
            .ToArray();
        return new AccountPasskeyOverview(
            credentials,
            maximum,
            MaximumNameLength,
            credentials.Length < maximum);
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

    private AccountPasskeyResult FromIdentityResult(
        IdentityResult result,
        AccountPasskeyOverview state) =>
        new(
            result.Succeeded,
            result.Errors
                .Select(error => new AccountSelfServiceError(
                    error.Code,
                    error.Description))
                .ToArray(),
            state);

    private static bool IsInvalidCeremony(Exception exception) =>
        exception is InvalidOperationException
            or ArgumentException
            or FormatException
            or JsonException;

    private int MaximumCredentials =>
        Math.Clamp(options.MaximumCredentialsPerAccount, 1, 100);

    private int MaximumNameLength =>
        Math.Clamp(options.MaximumNameLength, 1, 256);

    private int MaximumCredentialPayloadBytes =>
        Math.Clamp(options.MaximumCredentialPayloadBytes, 4096, 1_048_576);

    private const int MaximumUsernameLength = 256;
}
