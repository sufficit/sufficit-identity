using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.STS.Security;

/// <summary>
/// The authenticator key and the recovery codes are the second factor itself:
/// whoever reads them can produce the codes. ASP.NET Core Identity keeps them
/// in <c>usertokens</c> as plain text, so they go through the vault here,
/// bound to the user, provider and token name (plan C3).
/// </summary>
/// <remarks>
/// Values written before this existed stay readable while
/// <see cref="TwoFactorOptions.AcceptPlaintextSecrets"/> is on, and
/// <see cref="AuthenticationSecretMigrationWorker"/> encrypts them in place;
/// any mutation encrypts as well. With the option off, a plaintext value is an
/// error, never "no second factor", so nobody loses MFA by it.
/// </remarks>
internal static class AuthenticationSecretProtection
{
    /// <summary>Provider and names used by ASP.NET Core Identity's user store.</summary>
    public const string Provider = "[AspNetUserStore]";
    public const string AuthenticatorKey = "AuthenticatorKey";
    public const string RecoveryCodes = "RecoveryCodes";
    public const string KeyName = "user-authentication-secrets";

    public static readonly string[] Names = [AuthenticatorKey, RecoveryCodes];

    public static bool IsProtected(string loginProvider, string name) =>
        loginProvider == Provider && Names.Contains(name, StringComparer.Ordinal);

    /// <summary>Vault output, real (<c>v1.</c>) or pass-through (<c>pt1.</c>).</summary>
    public static bool IsCiphertext(string value) =>
        value.StartsWith("v1.", StringComparison.Ordinal) || value.StartsWith("pt1.", StringComparison.Ordinal);

    public static IReadOnlyDictionary<string, string> Aad(string userId, string loginProvider, string name) =>
        new Dictionary<string, string>
        {
            ["user_id"] = userId,
            ["login_provider"] = loginProvider,
            ["name"] = name,
        };

    public static Task<string> EncryptAsync(IKeyVault vault, string userId, string loginProvider, string name,
        string value, CancellationToken cancellationToken) =>
        vault.EncryptAsync(KeyName, value, Aad(userId, loginProvider, name), cancellationToken);
}

/// <summary>Restore proof for the second-factor secrets (plan C1/C3).</summary>
public static class SecondFactorSecretVerification
{
    /// <summary>Decrypts every stored authenticator key and recovery-code set; plain text counts as a failure.</summary>
    public static async Task<VaultVerificationResult> VerifyAsync(
        AppDbContext database, IKeyVault vault, CancellationToken cancellationToken = default)
    {
        var decrypted = 0;
        var failed = new List<string>();
        var tokens = await database.UserTokens.AsNoTracking()
            .Where(token => token.LoginProvider == AuthenticationSecretProtection.Provider
                && (token.Name == AuthenticationSecretProtection.AuthenticatorKey
                    || token.Name == AuthenticationSecretProtection.RecoveryCodes))
            .ToListAsync(cancellationToken);
        foreach (var token in tokens)
        {
            try
            {
                if (token.Value is null || !AuthenticationSecretProtection.IsCiphertext(token.Value))
                    throw new InvalidOperationException("plain text");
                await vault.DecryptAsync(token.Value,
                    AuthenticationSecretProtection.Aad(token.UserId, token.LoginProvider, token.Name), cancellationToken);
                decrypted++;
            }
            catch (Exception) when (!cancellationToken.IsCancellationRequested)
            {
                failed.Add($"{token.UserId}/{token.Name}");
            }
        }
        return new("second-factor", decrypted, failed);
    }
}

/// <summary>
/// The EF user store with the authenticator key and recovery codes encrypted
/// at rest. Everything else is the stock store.
/// </summary>
internal sealed class ProtectedSecretsUserStore(
    AppDbContext context,
    IKeyVault vault,
    TwoFactorOptions twoFactor,
    IdentityErrorDescriber? describer = null)
    : UserStore<ApplicationUser, ApplicationRole, AppDbContext, string,
        IdentityUserClaim<string>, IdentityUserRole<string>, IdentityUserLogin<string>,
        IdentityUserToken<string>, IdentityRoleClaim<string>, IdentityUserPasskey<string>>(context, describer)
{
    public override async Task SetTokenAsync(ApplicationUser user, string loginProvider, string name,
        string? value, CancellationToken cancellationToken)
    {
        // Fails closed: a vault error aborts the write instead of storing plain text.
        if (value is not null && AuthenticationSecretProtection.IsProtected(loginProvider, name))
            value = await AuthenticationSecretProtection.EncryptAsync(vault, user.Id, loginProvider, name, value, cancellationToken);
        await base.SetTokenAsync(user, loginProvider, name, value, cancellationToken);
    }

    public override async Task<string?> GetTokenAsync(ApplicationUser user, string loginProvider, string name,
        CancellationToken cancellationToken)
    {
        var value = await base.GetTokenAsync(user, loginProvider, name, cancellationToken);
        if (value is null || !AuthenticationSecretProtection.IsProtected(loginProvider, name))
            return value;
        if (AuthenticationSecretProtection.IsCiphertext(value))
            return await vault.DecryptStringAsync(value,
                AuthenticationSecretProtection.Aad(user.Id, loginProvider, name), cancellationToken);
        if (twoFactor.AcceptPlaintextSecrets)
            return value;
        throw new InvalidOperationException(
            $"The {name} of user {user.Id} is still stored as plain text and plain-text second factors are no longer accepted.");
    }
}
