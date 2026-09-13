using Microsoft.Extensions.Localization;
using Sufficit.Identity.UI.Management.Resources;

namespace Sufficit.Identity.UI.Management.Overview;

/// <summary>
/// Presentation-only copy and routing for module keys discovered from the
/// canonical runtime contract. Availability and authorization never originate
/// from this catalog.
/// </summary>
public sealed record ManagementModulePresentation(
    string Key,
    string Section,
    int SectionOrder,
    int Order,
    string Title,
    string Description,
    string Href,
    string Icon,
    bool ShowInNavigation = true);

public static class ManagementModulePresentations
{
    public static IReadOnlyList<ManagementModulePresentation> All(
        IStringLocalizer<Sufficit.Identity.UI.Management.Resources.ManagementResource> localizer) =>
    [
        new(
            "users",
            localizer["Capability.Group.Identity"].Value,
            10,
            10,
            localizer["Overview.Module.Users.Title"].Value,
            localizer["Overview.Module.Users.Description"].Value,
            "users",
            "users"),
        new(
            "claims",
            localizer["Capability.Group.Identity"].Value,
            10,
            20,
            localizer["Overview.Module.Claims.Title"].Value,
            localizer["Overview.Module.Claims.Description"].Value,
            "users",
            "shield",
            ShowInNavigation: false),
        new(
            "clients",
            localizer["Capability.Group.OAuthOidc"].Value,
            20,
            10,
            localizer["Overview.Module.Clients.Title"].Value,
            localizer["Overview.Module.Clients.Description"].Value,
            "clients",
            "key"),
        new(
            "service-accounts",
            localizer["Capability.Group.OAuthOidc"].Value,
            20,
            15,
            localizer["Overview.Module.ServiceAccounts.Title"].Value,
            localizer["Overview.Module.ServiceAccounts.Description"].Value,
            "service-accounts",
            "server"),
        new(
            "scopes",
            localizer["Capability.Group.OAuthOidc"].Value,
            20,
            20,
            "Scopes",
            localizer["Overview.Module.Scopes.Description"].Value,
            "scopes",
            "scope"),
        new("audiences", localizer["Capability.Group.OAuthOidc"].Value, 20, 25,
            localizer["Overview.Module.Audiences.Title"].Value,
            localizer["Overview.Module.Audiences.Description"].Value, "audiences", "server"),
        new(
            "authorizations",
            localizer["Capability.Group.OAuthOidc"].Value,
            20,
            30,
            localizer["Overview.Module.Authorizations.Title"].Value,
            localizer["Overview.Module.Authorizations.Description"].Value,
            "authorizations",
            "shield"),
        new(
            "branding",
            localizer["Capability.Group.Experience"].Value,
            30,
            10,
            "Branding",
            localizer["Overview.Module.Branding.Description"].Value,
            "branding",
            "palette"),
        new(
            "sessions",
            localizer["Capability.Group.Operations"].Value,
            40,
            10,
            localizer["Overview.Module.Sessions.Title"].Value,
            localizer["Overview.Module.Sessions.Description"].Value,
            "sessions",
            "clock"),
        new(
            "provisioning",
            localizer["Capability.Group.Operations"].Value,
            40,
            30,
            localizer["Overview.Module.Provisioning.Title"].Value,
            localizer["Overview.Module.Provisioning.Description"].Value,
            "provisioning",
            "workflow"),
        new(
            "operator-tokens",
            localizer["Capability.Group.Operations"].Value,
            40,
            20,
            localizer["Overview.Module.OperatorTokens.Title"].Value,
            localizer["Overview.Module.OperatorTokens.Description"].Value,
            "tokens",
            "key"),
        new(
            "audit",
            localizer["Capability.Group.Operations"].Value,
            40,
            30,
            localizer["Overview.Module.Audit.Title"].Value,
            localizer["Overview.Module.Audit.Description"].Value,
            "audit",
            "audit"),
        new(
            "metrics",
            localizer["Capability.Group.Operations"].Value,
            40,
            25,
            localizer["Overview.Module.Metrics.Title"].Value,
            localizer["Overview.Module.Metrics.Description"].Value,
            "metrics",
            "chart"),
        new("trusted-proxies", localizer["Capability.Group.Operations"].Value, 40, 45,
            localizer["Overview.Module.TrustedProxies.Title"].Value,
            localizer["Overview.Module.TrustedProxies.Description"].Value, "settings/trusted-proxies", "settings"),
        new(
            "database",
            localizer["Capability.Group.Operations"].Value,
            40,
            40,
            localizer["Overview.Module.Database.Title"].Value,
            localizer["Overview.Module.Database.Description"].Value,
            "database",
            "database")
    ];

    public static ManagementModulePresentation? Find(
        string key,
        IStringLocalizer<Sufficit.Identity.UI.Management.Resources.ManagementResource> localizer) =>
        All(localizer).FirstOrDefault(
            item => string.Equals(
                item.Key,
                key,
                StringComparison.Ordinal));
}
