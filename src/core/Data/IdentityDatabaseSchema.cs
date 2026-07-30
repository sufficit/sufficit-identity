namespace Sufficit.Identity.Core.Data;

/// <summary>
/// Canonical relational contract shared by runtime configuration, migrations
/// and schema tests.
/// </summary>
public static class IdentityDatabaseSchema
{
    public const string InitialMigrationId = "20260726213918_Initial";
    public const string BrandingThemesMigrationId = "20260729025623_AddBrandingThemes";
    public const string ManagementAuditMigrationId = "20260729221512_AddManagementAuditEvents";
    public const string ScimProvisioningMigrationId = "20260730220100_AddScimProvisioning";

    /// <summary>
    /// Migration history owned by the new Sufficit Identity model.
    /// It must not share the Skoruba/Duende <c>__efmigrationshistory</c> table.
    /// </summary>
    public const string MigrationsHistoryTable = "__sufficit_identity_migrations";

    public const int OpenIddictKeyLength = 100;
    public const int OpenIddictShortValueLength = 50;
    public const int OpenIddictClientIdLength = 100;
    public const int OpenIddictScopeNameLength = 200;
    public const int OpenIddictSubjectLength = 400;
    public const int OpenIddictTokenTypeLength = 150;
    public const int PasskeyCredentialIdLength = 1024;

    // Branding
    public const int BrandingUrlLength = 512;
    public const int BrandingColorLength = 7;   // #RRGGBB
    public const int BrandingNameLength = 100;
    public const int BrandingTitleLength = 200;

    // Management audit
    public const int AuditOperatorLength = 255;
    public const int AuditCapabilityLength = 150;
    public const int AuditResourceTypeLength = 100;
    public const int AuditResourceIdLength = 255;
    public const int AuditOutcomeLength = 50;
    public const int AuditReasonLength = 100;
    public const int AuditCorrelationLength = 100;
    public const int AuditAuthenticationMethodsLength = 255;

    // SCIM
    public const int ScimIdentifierLength = 255;
    public const int ScimDisplayNameLength = 256;
    public const int ScimProfileValueLength = 256;
    public const int ScimLanguageLength = 35;
    public const int ScimTimezoneLength = 100;
    public const int ScimConcurrencyStampLength = 64;
}
