using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using System.Security.Cryptography;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Clients;

internal sealed partial class ClientConfigurationDraftService
{
    private static ManagementClientProfile FindProfile(string? profile) =>
        Profiles.FirstOrDefault(item => string.Equals(
            item.Id,
            profile?.Trim(),
            StringComparison.OrdinalIgnoreCase))
        ?? throw new ManagementValidationException(
            "client_profile_invalid",
            "Choose an available application profile.",
            "profile");

    private static ManagementClientProfile WithAvailability(
        ManagementClientProfile profile,
        IdentityRuntimeCapabilitySnapshot capabilities)
    {
        var (available, reason) = profile.Id switch
        {
            ManagementClientProfiles.Web or
            ManagementClientProfiles.Spa or
            ManagementClientProfiles.Native or
            ManagementClientProfiles.Advanced =>
                (capabilities.SupportsGrant(
                    ManagementRuntimeCapabilities.AuthorizationCode),
                 "The runtime does not enable Authorization Code."),
            ManagementClientProfiles.Service =>
                (capabilities.SupportsGrant(
                    ManagementRuntimeCapabilities.ClientCredentials),
                 "The runtime does not enable Client Credentials."),
            ManagementClientProfiles.Device =>
                (capabilities.SupportsGrant(
                        ManagementRuntimeCapabilities.DeviceCode) &&
                 capabilities.SupportsFeature(
                     ManagementRuntimeCapabilities.DeviceAuthorization),
                 "The runtime does not enable Device Authorization."),
            _ => (false, "Unknown profile for this runtime."),
        };

        return profile with
        {
            IsAvailable = available,
            UnavailableReason = available ? null : reason,
        };
    }

    private static void EnsureProfileAvailable(
        ManagementClientProfile profile,
        IdentityRuntimeCapabilitySnapshot capabilities)
    {
        var resolved = WithAvailability(profile, capabilities);
        if (!resolved.IsAvailable)
        {
            throw new ManagementValidationException(
                "client_profile_unavailable",
                resolved.UnavailableReason ??
                    "This profile is not enabled in the current runtime.",
                "profile");
        }
    }

    private static ManagementClientDraftValues DefaultsFor(string profile) => profile switch
    {
        ManagementClientProfiles.Web => new()
        {
            ClientType = "confidential",
            AuthorizationCode = true,
            RefreshToken = true,
            RequirePar = true,
            Scopes = ["openid", "profile", "offline_access"],
        },
        ManagementClientProfiles.Spa => new()
        {
            ClientType = "public",
            AuthorizationCode = true,
            RequirePar = true,
            Scopes = ["openid", "profile"],
        },
        ManagementClientProfiles.Native => new()
        {
            ClientType = "public",
            AuthorizationCode = true,
            RefreshToken = true,
            Scopes = ["openid", "profile", "offline_access"],
        },
        ManagementClientProfiles.Service => new()
        {
            ClientType = "confidential",
            ClientCredentials = true,
        },
        ManagementClientProfiles.Device => new()
        {
            ClientType = "public",
            DeviceCode = true,
            RefreshToken = true,
            Scopes = ["openid", "profile", "offline_access"],
        },
        _ => new()
        {
            ClientType = "public",
            AuthorizationCode = true,
            Scopes = ["openid", "profile"],
        },
    };

    private static void NormalizeValues(ManagementClientDraftValues values)
    {
        values.ClientId = values.ClientId.Trim();
        values.DisplayName = values.DisplayName.Trim();
        values.ClientType = string.Equals(values.ClientType, "confidential", StringComparison.OrdinalIgnoreCase)
            ? "confidential"
            : "public";
        values.ConsentType = string.IsNullOrWhiteSpace(values.ConsentType)
            ? "explicit"
            : values.ConsentType.Trim().ToLowerInvariant();
        values.Scopes = NormalizeList(values.Scopes);
        values.RedirectUris = NormalizeList(values.RedirectUris);
        values.PostLogoutRedirectUris = NormalizeList(values.PostLogoutRedirectUris);
        values.FrontchannelLogoutUri = NullIfWhiteSpace(values.FrontchannelLogoutUri);
        values.BackchannelLogoutUri = NullIfWhiteSpace(values.BackchannelLogoutUri);
    }

    private static List<string> NormalizeList(IEnumerable<string>? values) =>
        (values ?? [])
            .Select(value => value?.Trim())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!)
            .Distinct(StringComparer.Ordinal)
            .ToList();

    private static string NormalizeStep(string? value) =>
        ManagementClientDraftSteps.All.FirstOrDefault(step => string.Equals(
            step,
            value,
            StringComparison.OrdinalIgnoreCase))
        ?? ManagementClientDraftSteps.Identity;

    private string Protect(
        ManagementClientDraftRecord row,
        ManagementClientDraftValues values) =>
        DraftProtector(row).Protect(JsonSerializer.Serialize(values, JsonOptions));

    private ManagementClientDraftValues Unprotect(ManagementClientDraftRecord row)
    {
        try
        {
            return JsonSerializer.Deserialize<ManagementClientDraftValues>(
                DraftProtector(row).Unprotect(row.ProtectedPayload),
                JsonOptions) ?? new ManagementClientDraftValues();
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException)
        {
            logger.LogError(
                exception,
                "Unable to read OAuth client draft {DraftId} for operator {OperatorSubject}.",
                row.Id,
                row.OwnerSubject);
            throw new ManagementValidationException(
                "client_draft_unreadable",
                "The draft could not be read safely. Abandon it and start another.");
        }
    }

    private IDataProtector DraftProtector(ManagementClientDraftRecord row) =>
        rootProtector.CreateProtector(row.OwnerSubject, row.Id.ToString("N"));

    private static void EnsureActive(ManagementClientDraftRecord row)
    {
        if (!string.Equals(row.Status, ActiveStatus, StringComparison.Ordinal))
        {
            throw new ManagementConflictException(
                "client_draft_completed",
                "This draft has already been completed.");
        }
    }

    private static string NewVersion() => Guid.NewGuid().ToString("N");

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static DateTimeOffset AsUtcOffset(DateTime value) =>
        new(DateTime.SpecifyKind(value, DateTimeKind.Utc));
}
