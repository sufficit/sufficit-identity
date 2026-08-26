using System.Globalization;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Security;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS;

/// <summary>
/// Applies explicitly configured per-client token lifetimes as a one-shot,
/// local maintenance operation. It deliberately is not a hosted startup
/// service: after a successful run the OpenIddict application record remains
/// the canonical, management-editable source of truth.
/// </summary>
public sealed class ClientTokenLifetimeReconciler(
    IOpenIddictApplicationManager applications,
    SufficitIdentityOptions options,
    ILogger<ClientTokenLifetimeReconciler> logger)
{
    public async Task<int> ReconcileAsync(
        CancellationToken cancellationToken = default)
    {
        var configured = options.Tokens.ClientOverrides
            .Where(entry => !string.IsNullOrWhiteSpace(entry.Key))
            .OrderBy(entry => entry.Key, StringComparer.Ordinal)
            .ToArray();
        if (configured.Length == 0)
        {
            throw new InvalidOperationException(
                "Sufficit:Identity:Tokens:ClientOverrides must contain at least one client.");
        }

        var updated = 0;
        foreach (var (configuredClientId, lifetime) in configured)
        {
            var clientId = configuredClientId.Trim();
            Validate(clientId, lifetime);

            var application = await applications.FindByClientIdAsync(
                clientId,
                cancellationToken) ?? throw new InvalidOperationException(
                    $"Configured token lifetime client '{clientId}' is not registered.");
            var descriptor = new OpenIddictApplicationDescriptor();
            await applications.PopulateAsync(
                descriptor,
                application,
                cancellationToken);

            var changed = false;
            changed |= ApplyMinutes(
                descriptor,
                Settings.TokenLifetimes.AccessToken,
                lifetime.AccessTokenLifetimeMinutes,
                descriptor.SetAccessTokenLifetime);
            changed |= ApplyMinutes(
                descriptor,
                Settings.TokenLifetimes.IdentityToken,
                lifetime.IdentityTokenLifetimeMinutes,
                descriptor.SetIdentityTokenLifetime);
            changed |= ApplyDays(
                descriptor,
                Settings.TokenLifetimes.RefreshToken,
                lifetime.RefreshTokenLifetimeDays,
                descriptor.SetRefreshTokenLifetime);

            if (!changed)
            {
                logger.LogInformation(
                    "Client {ClientId} token lifetimes already match the requested values.",
                    clientId);
                continue;
            }

            await applications.UpdateAsync(
                application,
                descriptor,
                cancellationToken);
            updated++;
            logger.LogInformation(
                "Reconciled token lifetimes for client {ClientId}: accessMinutes={AccessMinutes}, identityMinutes={IdentityMinutes}, refreshDays={RefreshDays}.",
                clientId,
                lifetime.AccessTokenLifetimeMinutes,
                lifetime.IdentityTokenLifetimeMinutes,
                lifetime.RefreshTokenLifetimeDays);
        }

        return updated;
    }

    private static bool ApplyMinutes(
        OpenIddictApplicationDescriptor descriptor,
        string setting,
        int? value,
        Func<TimeSpan?, OpenIddictApplicationDescriptor> apply)
    {
        if (value is null)
        {
            return false;
        }

        var expected = TimeSpan.FromMinutes(value.Value);
        if (Current(descriptor, setting) == expected)
        {
            return false;
        }

        apply(expected);
        return true;
    }

    private static bool ApplyDays(
        OpenIddictApplicationDescriptor descriptor,
        string setting,
        int? value,
        Func<TimeSpan?, OpenIddictApplicationDescriptor> apply)
    {
        if (value is null)
        {
            return false;
        }

        var expected = TimeSpan.FromDays(value.Value);
        if (Current(descriptor, setting) == expected)
        {
            return false;
        }

        apply(expected);
        return true;
    }

    private static TimeSpan? Current(
        OpenIddictApplicationDescriptor descriptor,
        string setting) =>
        descriptor.Settings.TryGetValue(setting, out var raw)
        && TimeSpan.TryParse(raw, CultureInfo.InvariantCulture, out var value)
            ? value
            : null;

    private static void Validate(
        string clientId,
        ClientTokenLifetimeOverrideOptions lifetime)
    {
        ArgumentNullException.ThrowIfNull(lifetime);
        if (lifetime.AccessTokenLifetimeMinutes is null
            && lifetime.IdentityTokenLifetimeMinutes is null
            && lifetime.RefreshTokenLifetimeDays is null)
        {
            throw new InvalidOperationException(
                $"Client '{clientId}' has no token lifetime value configured.");
        }

        ValidateRange(
            clientId,
            "access token",
            lifetime.AccessTokenLifetimeMinutes,
            TokenLifetimeLimits.MinimumAccessTokenLifetimeMinutes,
            TokenLifetimeLimits.MaximumAccessTokenLifetimeMinutes);
        ValidateRange(
            clientId,
            "identity token",
            lifetime.IdentityTokenLifetimeMinutes,
            TokenLifetimeLimits.MinimumIdentityTokenLifetimeMinutes,
            TokenLifetimeLimits.MaximumIdentityTokenLifetimeMinutes);
        ValidateRange(
            clientId,
            "refresh token",
            lifetime.RefreshTokenLifetimeDays,
            TokenLifetimeLimits.MinimumRefreshTokenLifetimeDays,
            TokenLifetimeLimits.MaximumRefreshTokenLifetimeDays);
    }

    private static void ValidateRange(
        string clientId,
        string token,
        int? value,
        int minimum,
        int maximum)
    {
        if (value is not null && (value < minimum || value > maximum))
        {
            throw new InvalidOperationException(
                $"Client '{clientId}' {token} lifetime must be between {minimum} and {maximum}.");
        }
    }
}
