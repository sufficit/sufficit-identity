using System.Globalization;
using OpenIddict.Abstractions;
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
    private const int MinimumAccessTokenLifetimeMinutes = 1;
    private const int MaximumAccessTokenLifetimeMinutes = 24 * 60;
    private const int MinimumIdentityTokenLifetimeMinutes = 1;
    private const int MaximumIdentityTokenLifetimeMinutes = 120;
    private const int MinimumRefreshTokenLifetimeDays = 1;
    private const int MaximumRefreshTokenLifetimeDays = 365;

    internal static void ValidateTokenLifetimes(
        int? accessTokenLifetimeMinutes,
        int? identityTokenLifetimeMinutes,
        int? refreshTokenLifetimeDays)
    {
        ValidateLifetime(
            accessTokenLifetimeMinutes,
            MinimumAccessTokenLifetimeMinutes,
            MaximumAccessTokenLifetimeMinutes,
            "accessTokenLifetimeMinutes",
            "access_token_lifetime_invalid",
            "Access token lifetime must be between 1 minute and 24 hours.");
        ValidateLifetime(
            identityTokenLifetimeMinutes,
            MinimumIdentityTokenLifetimeMinutes,
            MaximumIdentityTokenLifetimeMinutes,
            "identityTokenLifetimeMinutes",
            "identity_token_lifetime_invalid",
            "Identity token lifetime must be between 1 and 120 minutes.");
        ValidateLifetime(
            refreshTokenLifetimeDays,
            MinimumRefreshTokenLifetimeDays,
            MaximumRefreshTokenLifetimeDays,
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
}
