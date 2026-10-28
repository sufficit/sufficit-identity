using Microsoft.Extensions.Localization;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.UI.Management.Resources;
using ManagementUiResource =
    Sufficit.Identity.UI.Management.Resources.ManagementResource;

namespace Sufficit.Identity.UI.Management.Components;

/// <summary>
/// Resolves localized, human-facing copy for Management capabilities. The
/// explicit label map makes additions to the canonical capability catalog fail
/// tests until both supported languages explain the new permission.
/// </summary>
public static class ManagementCapabilityPresentation
{
    private static readonly IReadOnlyDictionary<string, string> LabelKeys =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [ManagementCapabilities.ClientsRead] = "Capability.Label.Read",
            [ManagementCapabilities.ClientsCreate] = "Capability.Label.Create",
            [ManagementCapabilities.ClientsUpdate] = "Capability.Label.Update",
            [ManagementCapabilities.ClientsDelete] = "Capability.Label.Delete",
            [ManagementCapabilities.BrandingRead] = "Capability.Label.Read",
            [ManagementCapabilities.BrandingManage] = "Capability.Label.Manage",
            [ManagementCapabilities.UsersRead] = "Capability.Label.Read",
            [ManagementCapabilities.UsersCreate] = "Capability.Label.Create",
            [ManagementCapabilities.UsersUpdate] = "Capability.Label.Update",
            [ManagementCapabilities.UsersDisable] = "Capability.Label.Disable",
            [ManagementCapabilities.UsersDelete] = "Capability.Label.Delete",
            [ManagementCapabilities.UsersReset] = "Capability.Label.ResetPassword",
            [ManagementCapabilities.UsersMfaReset] = "Capability.Label.ResetMfa",
            // F-8 (eval 2026-08-14): dedicated gate for the outbound
            // confirmation-email action (see UsersConfirmation).
            [ManagementCapabilities.UsersConfirmation] =
                "Capability.Label.ResendConfirmation",
            [ManagementCapabilities.UsersSystem] = "Capability.Label.SystemOnly",
            [ManagementCapabilities.ClaimsRead] = "Capability.Label.Read",
            [ManagementCapabilities.ClaimsCreate] = "Capability.Label.Create",
            [ManagementCapabilities.ClaimsUpdate] = "Capability.Label.Update",
            [ManagementCapabilities.ClaimsDelete] = "Capability.Label.Delete",
            [ManagementCapabilities.ClaimsSystem] = "Capability.Label.SystemOnly",
            [ManagementCapabilities.ScopesRead] = "Capability.Label.Read",
            [ManagementCapabilities.ScopesCreate] = "Capability.Label.Create",
            [ManagementCapabilities.ScopesUpdate] = "Capability.Label.Update",
            [ManagementCapabilities.ScopesDelete] = "Capability.Label.Delete",
            [ManagementCapabilities.ScopesGrant] = "Capability.Label.Grant",
            [ManagementCapabilities.SessionsRead] = "Capability.Label.Read",
            [ManagementCapabilities.SessionsRevoke] = "Capability.Label.Revoke",
            [ManagementCapabilities.AuthorizationsRead] = "Capability.Label.Read",
            [ManagementCapabilities.AuthorizationsRevoke] = "Capability.Label.Revoke",
            [ManagementCapabilities.AuditRead] = "Capability.Label.Read",
            [ManagementCapabilities.MaintenanceRead] = "Capability.Label.Read",
            [ManagementCapabilities.MaintenanceManage] = "Capability.Label.Manage",
            [ManagementCapabilities.DatabaseRead] = "Capability.Label.Read",
            [ManagementCapabilities.ProxiesRead] = "Capability.Label.Read",
            [ManagementCapabilities.ProxiesManage] = "Capability.Label.Manage",
            [ManagementCapabilities.MetricsRead] = "Capability.Label.Read",
            [ManagementCapabilities.MetricsManage] = "Capability.Label.Manage",
            [ManagementCapabilities.SecretsRead] = "Capability.Label.Read",
            [ManagementCapabilities.SecretsManage] = "Capability.Label.Manage",
            [ManagementCapabilities.SecretsResolve] = "Capability.Label.Resolve",
            [ManagementCapabilities.ProvisioningPreview] = "Capability.Label.Preview",
            [ManagementCapabilities.ProvisioningApply] = "Capability.Label.Apply",
            [ManagementCapabilities.TokensRead] = "Capability.Label.Read",
            [ManagementCapabilities.TokensIssue] = "Capability.Label.Issue",
            [ManagementCapabilities.TokensRevoke] = "Capability.Label.Revoke",
        };

    public static CapabilityCopy Get(
        string capability,
        IStringLocalizer<ManagementUiResource> localizer)
    {
        ArgumentNullException.ThrowIfNull(localizer);

        // A token issued before a rename still carries the retired spelling;
        // present it under its canonical name.
        capability = ManagementCapabilities.Normalize(capability);
        if (!LabelKeys.TryGetValue(capability, out var labelKey))
        {
            return new CapabilityCopy(
                localizer["Capability.Fallback.Label"],
                localizer["Capability.Fallback.Title", capability],
                localizer["Capability.Fallback.Description"]);
        }

        var keys = GetResourceKeys(capability, labelKey);
        return new CapabilityCopy(
            localizer[keys.Label],
            localizer[keys.Title],
            localizer[keys.Description]);
    }

    public static CapabilityResourceKeys GetResourceKeys(string capability)
    {
        if (!LabelKeys.TryGetValue(capability, out var labelKey))
        {
            throw new ArgumentOutOfRangeException(
                nameof(capability),
                capability,
                "Capability does not have an explicit presentation mapping.");
        }

        return GetResourceKeys(capability, labelKey);
    }

    public static bool HasExplicitCopy(string capability) =>
        LabelKeys.ContainsKey(capability);

    private static CapabilityResourceKeys GetResourceKeys(
        string capability,
        string labelKey)
    {
        var prefix = $"Capability.{capability}";
        return new CapabilityResourceKeys(
            labelKey,
            $"{prefix}.Title",
            $"{prefix}.Description");
    }
}

public sealed record CapabilityResourceKeys(
    string Label,
    string Title,
    string Description);

public sealed record CapabilityCopy(
    string Label,
    string HelpTitle,
    string HelpText);
