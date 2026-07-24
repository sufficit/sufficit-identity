namespace Sufficit.Identity.Core.Data;

/// <summary>
/// Canonical relational contract shared by runtime configuration, migrations
/// and schema tests.
/// </summary>
public static class IdentityDatabaseSchema
{
    public const string InitialMigrationId = "20260724213612_Initial";

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
}
