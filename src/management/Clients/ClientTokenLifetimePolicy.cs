using System.Globalization;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Clients;

/// <summary>
/// Bounds and persistence for the per-client token lifetime overrides.
/// </summary>
/// <remarks>
/// Extracted from <c>ClientManagementService</c>. A lifetime override widens
/// the window in which a stolen token stays usable, so the bounds are a
/// security control rather than a convenience — hence keeping them, their
/// validation and their read/write conversions in one place. Behavior is
/// unchanged; reason codes and messages are part of the API contract and are
/// reproduced exactly.
/// </remarks>
internal static class ClientTokenLifetimePolicy
{
    internal static void ValidateTokenLifetimes(
        int? accessTokenLifetimeMinutes,
        int? identityTokenLifetimeMinutes,
        int? refreshTokenLifetimeDays)
    {
        ValidateLifetime(
            accessTokenLifetimeMinutes,
            TokenLifetimeLimits.MinimumAccessTokenLifetimeMinutes,
            TokenLifetimeLimits.MaximumAccessTokenLifetimeMinutes,
            "accessTokenLifetimeMinutes",
            "access_token_lifetime_invalid",
            "Access token lifetime must be between 1 minute and 7 days.");
        ValidateLifetime(
            identityTokenLifetimeMinutes,
            TokenLifetimeLimits.MinimumIdentityTokenLifetimeMinutes,
            TokenLifetimeLimits.MaximumIdentityTokenLifetimeMinutes,
            "identityTokenLifetimeMinutes",
            "identity_token_lifetime_invalid",
            "Identity token lifetime must be between 1 and 120 minutes.");
        ValidateLifetime(
            refreshTokenLifetimeDays,
            TokenLifetimeLimits.MinimumRefreshTokenLifetimeDays,
            TokenLifetimeLimits.MaximumRefreshTokenLifetimeDays,
            "refreshTokenLifetimeDays",
            "refresh_token_lifetime_invalid",
            "Refresh token lifetime must be between 1 and 365 days.");
    }

    private static void ValidateLifetime(
        int? value,
        int minimum,
        int maximum,
        string field,
        string reasonCode,
        string message)
    {
        if (value is not null && (value < minimum || value > maximum))
        {
            throw new ManagementValidationException(reasonCode, message, field);
        }
    }

    internal static void ApplyTokenLifetimes(
        OpenIddictApplicationDescriptor descriptor,
        int? accessTokenLifetimeMinutes,
        int? identityTokenLifetimeMinutes,
        int? refreshTokenLifetimeDays,
        bool clearAccessTokenLifetime = false,
        bool clearIdentityTokenLifetime = false,
        bool clearRefreshTokenLifetime = false)
    {
        // A clear flag explicitly removes an override. Without it, null means
        // the caller did not manage that field, preserving older clients.
        if (clearAccessTokenLifetime)
        {
            descriptor.SetAccessTokenLifetime(null);
        }
        else if (accessTokenLifetimeMinutes is { } access)
        {
            descriptor.SetAccessTokenLifetime(TimeSpan.FromMinutes(access));
        }
        if (clearIdentityTokenLifetime)
        {
            descriptor.SetIdentityTokenLifetime(null);
        }
        else if (identityTokenLifetimeMinutes is { } identity)
        {
            descriptor.SetIdentityTokenLifetime(TimeSpan.FromMinutes(identity));
        }
        if (clearRefreshTokenLifetime)
        {
            descriptor.SetRefreshTokenLifetime(null);
        }
        else if (refreshTokenLifetimeDays is { } refresh)
        {
            descriptor.SetRefreshTokenLifetime(TimeSpan.FromDays(refresh));
        }
    }

    internal static int? GetLifetimeMinutes(
        IReadOnlyDictionary<string, string> settings,
        string key)
    {
        if (!settings.TryGetValue(key, out var value)
            || !TimeSpan.TryParse(value, CultureInfo.InvariantCulture, out var lifetime)
            || lifetime <= TimeSpan.Zero)
        {
            return null;
        }

        var minutes = (int)Math.Round(lifetime.TotalMinutes,
            MidpointRounding.AwayFromZero);
        return minutes > 0 ? minutes : null;
    }

    internal static int? GetLifetimeDays(
        IReadOnlyDictionary<string, string> settings,
        string key)
    {
        if (!settings.TryGetValue(key, out var value)
            || !TimeSpan.TryParse(value, CultureInfo.InvariantCulture, out var lifetime)
            || lifetime <= TimeSpan.Zero)
        {
            return null;
        }

        var days = (int)Math.Round(lifetime.TotalDays,
            MidpointRounding.AwayFromZero);
        return days > 0 ? days : null;
    }

    /// <summary>
    /// The application's own limit on the sign-in age for delegated
    /// credentials. Like a lifetime override, it widens a window an attacker
    /// with a stolen session could use, so it shares the same bounds checks.
    /// </summary>
    internal static void ValidateDelegationSignInAge(int? hours)
    {
        if (hours is not null && (hours < DelegationSignInAge.MinimumHours || hours > DelegationSignInAge.MaximumHours))
        {
            throw new ManagementValidationException(
                "delegation_max_auth_age_invalid",
                "The sign-in age for delegation must be between 1 and 168 hours.",
                "delegationMaxAuthAgeHours");
        }
    }

    internal static void ApplyDelegationSignInAge(
        OpenIddictApplicationDescriptor descriptor, int? hours, bool clear = false)
    {
        if (clear)
        {
            descriptor.Settings.Remove(DelegationSignInAge.ClientSetting);
        }
        else if (hours is { } value)
        {
            descriptor.Settings[DelegationSignInAge.ClientSetting] =
                value.ToString(CultureInfo.InvariantCulture);
        }
    }
}
