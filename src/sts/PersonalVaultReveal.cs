using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Vault;
using Sufficit.Identity.Vault;
using static Sufficit.Identity.Management.Vault.PersonalVaultRevealStatus;

namespace Sufficit.Identity.STS;

internal sealed class PersonalVaultReveal(
    IVaultNamedSecretStore store,
    VaultOptions options,
    UserManager<ApplicationUser> users,
    IDataProtectionProvider protection,
    TimeProvider clock,
    ILogger<PersonalVaultReveal> logger) : IPersonalVaultReveal
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);

    public async Task<PersonalVaultRevealResult> RevealAsync(
        ClaimsPrincipal principal, string name, string code, string? grant,
        CancellationToken cancellationToken = default)
    {
        if (!options.Enabled)
            return new(Unavailable);

        var sid = principal.FindFirstValue(OidcSessionClaimsPrincipalFactory.SessionIdClaimType);
        if (principal.Identity?.IsAuthenticated != true || string.IsNullOrEmpty(sid))
            return new(Unauthorized);

        var user = await users.GetUserAsync(principal);
        if (user is null)
            return new(Unauthorized);
        var stamp = await users.GetSecurityStampAsync(user);
        if (string.IsNullOrEmpty(stamp) || !string.Equals(stamp,
                principal.FindFirstValue(users.Options.ClaimsIdentity.SecurityStampClaimType),
                StringComparison.Ordinal))
            return new(Unauthorized);

        if (!await users.GetTwoFactorEnabledAsync(user)
            || string.IsNullOrEmpty(await users.GetAuthenticatorKeyAsync(user)))
            return new(AuthenticatorRequired);

        // Apply the persisted Identity attempt limit even to legacy accounts
        // whose LockoutEnabled flag exempts them from sign-in lockout.
        if (await users.GetLockoutEndDateAsync(user) is { } lockoutEnd
            && lockoutEnd >= clock.GetUtcNow())
            return new(LockedOut);

        var protector = protection.CreateProtector(
            "Sufficit.Identity.Vault.PersonalReveal.v1", user.Id, sid, stamp);
        var expires = ReadExpiry(protector, grant);
        string? newGrant = null;
        if (expires <= clock.GetUtcNow())
        {
            if (string.IsNullOrEmpty(code))
                return new(Challenge);

            var valid = code.Length == 6 && code.All(char.IsAsciiDigit)
                && await users.VerifyTwoFactorTokenAsync(
                    user, users.Options.Tokens.AuthenticatorTokenProvider, code);
            if (!valid)
            {
                var failed = await users.AccessFailedAsync(user);
                return new(failed.Succeeded ? InvalidCode : Unavailable);
            }

            var reset = await users.ResetAccessFailedCountAsync(user);
            if (!reset.Succeeded)
                return new(Unavailable);

            // Round-trip the same instant even across replicas and retries.
            expires = clock.GetUtcNow().Add(Lifetime);
            newGrant = protector.Protect(expires.UtcTicks.ToString(CultureInfo.InvariantCulture));
        }

        string storedName;
        try
        {
            storedName = UserVaultPersonalSecretService.ToStoredName(name);
        }
        catch (ArgumentException)
        {
            return new(NotFound);
        }

        var value = await store.GetSecretAsync(storedName,
            UserVaultPersonalSecretService.ContextFor(user.Id), cancellationToken);
        var remaining = expires - clock.GetUtcNow();
        if (remaining <= TimeSpan.Zero)
            return new(Challenge);
        if (value is null)
            return new(NotFound);

        logger.LogInformation("User {UserId} revealed a personal Vault secret.", user.Id);
        return new(Revealed, value, newGrant, remaining);
    }

    private static DateTimeOffset ReadExpiry(IDataProtector protector, string? grant)
    {
        if (string.IsNullOrEmpty(grant))
            return DateTimeOffset.MinValue;

        try
        {
            var payload = protector.Unprotect(grant);
            return long.TryParse(payload, NumberStyles.None, CultureInfo.InvariantCulture, out var ticks)
                && ticks <= DateTimeOffset.MaxValue.UtcTicks
                ? new DateTimeOffset(ticks, TimeSpan.Zero)
                : DateTimeOffset.MinValue;
        }
        catch (CryptographicException)
        {
            return DateTimeOffset.MinValue;
        }
    }
}
