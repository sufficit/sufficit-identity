using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Provisioning;
using System.Globalization;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Clients;

internal sealed partial class ClientManagementService
{
    private async Task<ManagementClientDetail> ToDetailAsync(
        object application,
        CancellationToken cancellationToken)
    {
        var permissions = await applications.GetPermissionsAsync(
            application,
            cancellationToken);
        var requirements = await applications.GetRequirementsAsync(
            application,
            cancellationToken);
        var redirectUris = await applications.GetRedirectUrisAsync(
            application,
            cancellationToken);
        var postLogoutRedirectUris =
            await applications.GetPostLogoutRedirectUrisAsync(
                application,
                cancellationToken);
        var settings = await applications.GetSettingsAsync(
            application,
            cancellationToken);

        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(
            descriptor,
            application,
            cancellationToken);

        var entity = application as OpenIddictEntityFrameworkCoreApplication;
        var now = DateTime.UtcNow;
        var activeAdditionalCredentials = entity?.ClientId is { } clientId
            ? await database.OAuthClientCredentials
                .AsNoTracking()
                .CountAsync(credential =>
                    credential.ClientId == clientId
                    && credential.Kind == OAuthClientCredentialKinds.SharedSecret
                    && credential.RevokedAtUtc == null
                    && (credential.NotBeforeUtc == null || credential.NotBeforeUtc <= now)
                    && (credential.ExpiresAtUtc == null || credential.ExpiresAtUtc > now),
                    cancellationToken)
            : 0;
        var hasPrimarySecret = !string.IsNullOrWhiteSpace(entity?.ClientSecret);
        var tlsCertificates = ClientTlsCertificateCredential.Read(
            entity?.JsonWebKeySet,
            DateTimeOffset.UtcNow);
        var authenticationMethods = ClientCredentialPolicy.GetAuthenticationMethods(
            hasPrimarySecret || activeAdditionalCredentials > 0,
            entity?.JsonWebKeySet,
            tlsCertificates);

        return new ManagementClientDetail(
            Id: (string)(await applications.GetIdAsync(
                application,
                cancellationToken))!,
            ClientId: (string)(await applications.GetClientIdAsync(
                application,
                cancellationToken))!,
            DisplayName: (string?)await applications.GetDisplayNameAsync(
                application,
                cancellationToken),
            Type: (string?)await applications.GetClientTypeAsync(
                application,
                cancellationToken),
            ConsentType: (string?)await applications.GetConsentTypeAsync(
                application,
                cancellationToken),
            Permissions: permissions.Order(StringComparer.Ordinal).ToArray(),
            Requirements: requirements.Order(StringComparer.Ordinal).ToArray(),
            RedirectUris: redirectUris
                .Order(StringComparer.Ordinal)
                .ToArray(),
            PostLogoutRedirectUris: postLogoutRedirectUris
                .Order(StringComparer.Ordinal)
                .ToArray(),
            FrontchannelLogoutUri: GetSetting(
                settings,
                "frontchannel_logout_uri"),
            FrontchannelLogoutSessionRequired: GetBooleanSetting(
                settings,
                "frontchannel_logout_session_required"),
            BackchannelLogoutUri: GetSetting(
                settings,
                "backchannel_logout_uri"),
            BackchannelLogoutSessionRequired: GetBooleanSetting(
                settings,
                "backchannel_logout_session_required"),
            Version: entity?.ConcurrencyToken,
            IsManifestManaged: descriptor.Properties.ContainsKey(
                OpenIddictManifestProvisioner.SchemaVersionProperty),
            JwksUri: GetSetting(settings, "jwks_uri"),
            AccessTokenLifetimeMinutes: ClientTokenLifetimePolicy.GetLifetimeMinutes(
                settings,
                OpenIddictConstants.Settings.TokenLifetimes.AccessToken),
            IdentityTokenLifetimeMinutes: ClientTokenLifetimePolicy.GetLifetimeMinutes(
                settings,
                OpenIddictConstants.Settings.TokenLifetimes.IdentityToken),
            RefreshTokenLifetimeDays: ClientTokenLifetimePolicy.GetLifetimeDays(
                settings,
                OpenIddictConstants.Settings.TokenLifetimes.RefreshToken),
            GlobalAccessTokenLifetimeMinutes: configuration.GetValue<int?>(
                "Sufficit:Identity:Tokens:AccessTokenLifetimeMinutes") ?? 60,
            GlobalIdentityTokenLifetimeMinutes: configuration.GetValue<int?>(
                "Sufficit:Identity:Tokens:IdentityTokenLifetimeMinutes") ?? 20,
            GlobalRefreshTokenLifetimeDays: configuration.GetValue<double?>(
                "Sufficit:Identity:Tokens:RefreshTokenLifetimeDays") ?? 14,
            Origin: descriptor.Properties.ContainsKey(
                    OpenIddictManifestProvisioner.SchemaVersionProperty)
                ? "manifest"
                : descriptor.Properties.ContainsKey(
                    DynamicClientRegistrationProperties.Origin)
                    ? DynamicClientRegistrationProperties.OriginValue
                    : "manual",
            RegisteredAtUtc: GetInstantProperty(
                descriptor.Properties,
                DynamicClientRegistrationProperties.RegisteredAt),
            RegisteredAnonymously: GetBooleanProperty(
                descriptor.Properties,
                DynamicClientRegistrationProperties.Anonymous),
            RegisteredFromAddress: GetStringProperty(
                descriptor.Properties,
                DynamicClientRegistrationProperties.RemoteAddress),
            RegisteredUserAgent: GetStringProperty(
                descriptor.Properties,
                DynamicClientRegistrationProperties.UserAgent),
            HasClientSecret: hasPrimarySecret || activeAdditionalCredentials > 0,
            JwksJson: ClientTlsCertificateCredential
                .ExtractPrivateKeyJwtKeys(entity?.JsonWebKeySet)?.ToString(),
            AuthenticationMethods: authenticationMethods,
            ActiveCredentialCount:
                activeAdditionalCredentials + (hasPrimarySecret ? 1 : 0),
            NativeReturnUris: ReadNativeReturnUris(descriptor.Properties),
            DeviceCloseFallbackUrl: DeviceCloseFallbackPolicy.Read(descriptor.Properties));
    }

    /// <summary>
    /// Writes the <c>native_return_uris</c> extension metadata into the client
    /// property bag, removing the key entirely when nothing is registered so a
    /// client that uses none carries no trace of the feature.
    /// </summary>
    private static void SetNativeReturnUris(
        IDictionary<string, JsonElement> properties,
        IReadOnlyList<string> values)
    {
        properties.Remove(NativeReturnUriPolicy.PropertyKey);
        if (values.Count == 0)
        {
            return;
        }

        properties[NativeReturnUriPolicy.PropertyKey] =
            JsonSerializer.SerializeToElement(values);
    }

    /// <summary>
    /// Writes the <c>device_close_fallback_url</c> extension metadata into the
    /// client property bag, removing the key entirely when nothing is
    /// registered — a client that uses no fallback carries no trace of it.
    /// </summary>
    private static void SetDeviceCloseFallback(
        IDictionary<string, JsonElement> properties,
        string? url)
    {
        properties.Remove(DeviceCloseFallbackPolicy.PropertyKey);
        if (url is null)
        {
            return;
        }

        properties[DeviceCloseFallbackPolicy.PropertyKey] =
            JsonSerializer.SerializeToElement(url);
    }

    private static IReadOnlyList<string> ReadNativeReturnUris(
        IReadOnlyDictionary<string, JsonElement> properties) =>
        properties.TryGetValue(
            NativeReturnUriPolicy.PropertyKey,
            out var value)
        && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray()
                .Where(element => element.ValueKind == JsonValueKind.String)
                .Select(element => element.GetString()!)
                .Where(uri => !string.IsNullOrWhiteSpace(uri))
                .ToArray()
            : [];

    private static string? GetStringProperty(
        IReadOnlyDictionary<string, JsonElement> properties,
        string key) =>
        properties.TryGetValue(key, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static bool GetBooleanProperty(
        IReadOnlyDictionary<string, JsonElement> properties,
        string key) =>
        properties.TryGetValue(key, out var value)
        && value.ValueKind == JsonValueKind.True;

    private static DateTimeOffset? GetInstantProperty(
        IReadOnlyDictionary<string, JsonElement> properties,
        string key) =>
        GetStringProperty(properties, key) is { } raw
        && DateTimeOffset.TryParse(
            raw,
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AdjustToUniversal
                | System.Globalization.DateTimeStyles.AssumeUniversal,
            out var parsed)
            ? parsed
            : null;

    private static void AddLogoutSettings(
        IDictionary<string, string> settings,
        Uri? frontchannelLogoutUri,
        bool frontchannelSessionRequired,
        Uri? backchannelLogoutUri,
        bool backchannelSessionRequired)
    {
        if (frontchannelLogoutUri is not null)
        {
            settings["frontchannel_logout_uri"] = frontchannelLogoutUri.AbsoluteUri;
            settings["frontchannel_logout_session_required"] =
                frontchannelSessionRequired ? "true" : "false";
        }

        if (backchannelLogoutUri is not null)
        {
            settings["backchannel_logout_uri"] = backchannelLogoutUri.AbsoluteUri;
            settings["backchannel_logout_session_required"] =
                backchannelSessionRequired ? "true" : "false";
        }
    }

    private static string? GetSetting(
        System.Collections.Immutable.ImmutableDictionary<string, string> settings,
        string key) =>
        settings.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : null;

    private static bool GetBooleanSetting(
        System.Collections.Immutable.ImmutableDictionary<string, string> settings,
        string key) =>
        settings.TryGetValue(key, out var value) &&
        bool.TryParse(value, out var result) &&
        result;

    private static string ResolveOrigin(string? properties) =>
        IsManifestManaged(properties) ? "manifest"
        : IsSelfRegistered(properties) ? "dcr"
        : "manual";

    private static bool IsSelfRegistered(string? properties) =>
        properties?.Contains(
            DynamicClientRegistrationProperties.Origin,
            StringComparison.Ordinal) is true;

    private static bool IsManifestManaged(string? properties) =>
        properties?.Contains(
            OpenIddictManifestProvisioner.SchemaVersionProperty,
            StringComparison.Ordinal) is true;

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
