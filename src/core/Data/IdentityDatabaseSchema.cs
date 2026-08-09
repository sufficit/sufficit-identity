namespace Sufficit.Identity.Core.Data;

/// <summary>
/// Canonical relational contract shared by runtime configuration, migrations
/// and schema tests.
/// </summary>
public static class IdentityDatabaseSchema
{
    public const int MetricsProviderLength = 50;
    public const int MetricsEndpointLength = 1024;
    public const int MetricsDatabaseLength = 255;
    public const int MetricsAuthorizationSchemeLength = 32;
    public const int MetricsUsernameLength = 255;
    public const int MetricsClientIdLength = 255;
    public const int MetricsEventTypeLength = 64;
    public const int MetricsEndpointTypeLength = 64;
    public const int MetricsGrantTypeLength = 100;
    public const int MetricsOutcomeLength = 32;
    public const int MetricsSubjectHashLength = 64;
    public const string InitialMigrationId = "20260726213918_Initial";
    public const string BrandingThemesMigrationId = "20260729025623_AddBrandingThemes";
    public const string ManagementAuditMigrationId = "20260729221512_AddManagementAuditEvents";
    public const string ScimProvisioningMigrationId = "20260730220100_AddScimProvisioning";
    public const string UserCreatedAtMigrationId = "20260804020337_AddUserCreatedAtUtc";
    public const string SsfStreamsMigrationId = "20260805202819_AddSsfStreams";
    public const string OidcUserSessionsMigrationId = "20260806131249_AddOidcUserSessions";
    public const string VaultKeysMigrationId = "20260806162913_AddVaultKeys"; // gitleaks:allow
    public const string VaultSecretsMigrationId = "20260808173938_AddVaultSecrets"; // gitleaks:allow
    public const string VaultPersonalSecretsMigrationId = "20260808191220_AddVaultPersonalSecrets"; // gitleaks:allow
    public const string VaultSigningKeyJwkMigrationId = "20260808174200_AddVaultSigningKeyJwk"; // gitleaks:allow
    public const string VaultSigningKeyLifecycleMigrationId = "20260809224037_AddVaultSigningKeyLifecycle"; // gitleaks:allow
    public const string IdentityApplicationMetricsMigrationId = "20260807020859_AddIdentityApplicationMetrics";
    public const string SsfStreamSecurityMigrationId = "20260807135147_HardenSsfStreams";
    public const string AtomicProtocolStateMigrationId = "20260807140821_AddAtomicProtocolState";
    public const string ManagementClientDraftsMigrationId = "20260807161036_AddManagementClientDrafts";

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

    // Management OAuth/OIDC application drafts
    public const int ManagementDraftOwnerLength = 255;
    public const int ManagementDraftProfileLength = 40;
    public const int ManagementDraftStepLength = 32;
    public const int ManagementDraftStatusLength = 24;
    public const int ManagementDraftVersionLength = 32;

    // SCIM
    public const int ScimIdentifierLength = 255;
    public const int ScimDisplayNameLength = 256;
    public const int ScimProfileValueLength = 256;
    public const int ScimLanguageLength = 35;
    public const int ScimTimezoneLength = 100;
    public const int ScimConcurrencyStampLength = 64;

    // SSF / CAEP stream management (RFC 8933)
    public const int SsfStreamIdLength = 64;          // opaque stream id
    public const int SsfAudienceLength = 256;
    public const int SsfDeliveryMethodLength = 32;    // urn:ietf:rfc:8935 / 8934
    public const int SsfEndpointLength = 512;
    public const int SsfStatusLength = 16;            // enabled | disabled | paused
    public const int SsfVerificationStateLength = 16; // pending | verified
    public const int SsfScopeLength = 512;            // subject scope JSON
    public const int SsfEventsRequestedLength = 1024; // events JSON array
    public const int SsfDescriptionLength = 256;
    public const int SsfJtiLength = 64;               // SET jti (poll queue)
    public const int SsfOwnerClientIdLength = 100;
    public const int SsfChallengeHashLength = 43;     // base64url SHA-256
    public const int SsfDeliveryKeyLength = 64;       // lowercase hex SHA-256

    // Protocol replay / one-shot state
    public const int ProtocolStateKeyLength = 64;
    public const int ProtocolStateValueLength = 400;
    public const int ProtocolStateJsonLength = 2048;
    public const int ProtocolStateStatusLength = 16;
    public const int CibaBindingMessageLength = 180;

    // OIDC server-side sessions (browser SSO sessions for the Identity cookie)
    public const int OidcSessionIdLength = 64;          // the sid (32 random bytes base64url)
    public const int OidcSessionUserAgentLength = 512;
    public const int OidcSessionRemoteIpLength = 64;

    // Vault keys (internal secret vault — wrapped DEKs / item keys)
    public const int VaultKeyNameLength = 64;
    public const int VaultPurposeLength = 16;           // symmetric | signing
    public const int VaultSigningStateLength = 16;
    public const int VaultLifecycleOperationIdLength = 80;
    public const int VaultLifecycleActionLength = 24;
    public const int VaultLifecycleReasonLength = 256;
    public const int VaultLockOwnerLength = 64;
    public const int VaultSecretNameLength = 128;
    public const int VaultSecretUpdatedByLength = 128;
    public const int VaultPersonalSecretOwnerLength = 255;
    public const int VaultPersonalSecretNamespaceLength = 64;
}
