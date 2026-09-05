using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class DatabaseSchemaContractTests
{
    [Fact]
    public void MySql_model_matches_the_established_identity_and_openiddict_contract()
    {
        using var context = CreateContext();
        var model = context.Model;

        var application = RequiredEntity<OpenIddictEntityFrameworkCoreApplication>(model);
        AssertProperty(application, "Id", "id", "varchar(100)", 100, nullable: false);
        AssertProperty(application, "ClientId", "client_id", "varchar(100)", 100, nullable: true);
        AssertIndex(application, "AK_OpenIddictApplications_ClientId", unique: true,
            "ClientId");

        var authorization = RequiredEntity<OpenIddictEntityFrameworkCoreAuthorization>(model);
        AssertProperty(authorization, "Id", "id", "varchar(100)", 100, nullable: false);
        AssertProperty(authorization, "ApplicationId", "application_id", "varchar(100)", 100, nullable: true);
        AssertProperty(authorization, "Subject", "subject", "varchar(400)", 400, nullable: true);
        AssertIndex(authorization,
            "IX_OpenIddictAuthorizations_ApplicationId_Status_Subject_Type",
            unique: false, "ApplicationId", "Status", "Subject", "Type");

        var scope = RequiredEntity<OpenIddictEntityFrameworkCoreScope>(model);
        AssertProperty(scope, "Id", "id", "varchar(100)", 100, nullable: false);
        AssertProperty(scope, "Name", "name", "varchar(200)", 200, nullable: true);
        AssertIndex(scope, "AK_OpenIddictScopes_Name", unique: true, "Name");

        var token = RequiredEntity<OpenIddictEntityFrameworkCoreToken>(model);
        AssertProperty(token, "Id", "id", "varchar(100)", 100, nullable: false);
        AssertProperty(token, "ReferenceId", "reference_id", "varchar(100)", 100, nullable: true);
        AssertProperty(token, "Subject", "subject", "varchar(400)", 400, nullable: true);
        AssertProperty(token, "Type", "type", "varchar(150)", 150, nullable: true);
        AssertIndex(token, "AK_OpenIddictTokens_ReferenceId", unique: true, "ReferenceId");
        AssertIndex(token, "IX_OpenIddictTokens_ApplicationId_Status_Subject_Type",
            unique: false, "ApplicationId", "Status", "Subject", "Type");
        AssertIndex(token, "IX_OpenIddictTokens_AuthorizationId",
            unique: false, "AuthorizationId");

        var passkey = RequiredEntity<IdentityUserPasskey<string>>(model);
        Assert.Equal("userpasskeys", passkey.GetTableName());
        Assert.Equal(["CredentialId"], passkey.FindPrimaryKey()!.Properties.Select(p => p.Name));
        AssertProperty(passkey, "CredentialId", "credentialid", "varbinary(1024)", 1024, nullable: false);
        AssertProperty(passkey, "UserId", "userid", "varchar(255)", null, nullable: false);
        AssertIndex(passkey, "IX_userpasskeys_userid", unique: false, "UserId");

        var passkeyData = model.GetEntityTypes().Single(entity =>
            entity.IsOwned() && entity.ClrType == typeof(IdentityPasskeyData));
        AssertOwnedColumn(passkeyData, "PublicKey", "publickey");
        AssertOwnedColumn(passkeyData, "CreatedAt", "createdat", "datetime(6)");
        AssertOwnedColumn(passkeyData, "Transports", "transports");
        AssertOwnedColumn(passkeyData, "AttestationObject", "attestationobject");
        AssertOwnedColumn(passkeyData, "ClientDataJson", "clientdatajson");

        var dataProtection = RequiredEntity<DataProtectionKey>(model);
        AssertProperty(dataProtection, "Id", "id", "int", null, nullable: false);
        AssertProperty(dataProtection, "FriendlyName", "friendlyname", "longtext", null, nullable: true);
        AssertProperty(dataProtection, "Xml", "xml", "longtext", null, nullable: true);

        var user = RequiredEntity<ApplicationUser>(model);
        AssertProperty(user, "CreatedAtUtc", "createdatutc", "datetime(6)", null, nullable: false);
        AssertIndex(user, "IX_users_createdatutc", unique: false, "CreatedAtUtc");

        var audit = RequiredEntity<ManagementAuditEvent>(model);
        Assert.Equal("managementauditevents", audit.GetTableName());
        AssertProperty(audit, "Id", "id", "bigint", null, nullable: false);
        AssertProperty(
            audit,
            "OperatorSubject",
            "operatorsubject",
            "varchar(255)",
            255,
            nullable: false);
        AssertProperty(
            audit,
            "Capability",
            "capability",
            "varchar(150)",
            150,
            nullable: false);
        AssertIndex(
            audit,
            "IX_managementauditevents_occurredatutc",
            unique: false,
            "OccurredAtUtc");
        AssertIndex(
            audit,
            "IX_managementauditevents_resource",
            unique: false,
            "ResourceType",
            "ResourceId");

        var clientCredential = RequiredEntity<OAuthClientCredential>(model);
        Assert.Equal("oauthclientcredentials", clientCredential.GetTableName());
        AssertProperty(clientCredential, "Id", "id", "char(36)", null,
            nullable: false);
        AssertProperty(clientCredential, "ClientId", "clientid", "varchar(100)",
            100, nullable: false);
        AssertProperty(clientCredential, "Kind", "kind", "varchar(32)", 32,
            nullable: false);
        AssertProperty(clientCredential, "Label", "label", "varchar(100)", 100,
            nullable: false);
        AssertProperty(clientCredential, "SecretHash", "secrethash", "varchar(1024)",
            1024, nullable: false);
        AssertProperty(clientCredential, "ConcurrencyToken", "concurrencytoken",
            "varchar(32)", 32, nullable: false);
        Assert.True(clientCredential.FindProperty("ConcurrencyToken")!.IsConcurrencyToken);
        AssertIndex(clientCredential,
            "IX_oauthclientcredentials_client_kind_status",
            unique: false,
            "ClientId", "Kind", "RevokedAtUtc", "ExpiresAtUtc");

        var scimProfile = RequiredEntity<ScimUserProfile>(model);
        Assert.Equal("scimuserprofiles", scimProfile.GetTableName());
        AssertProperty(
            scimProfile,
            "UserId",
            "userid",
            "varchar(255)",
            255,
            nullable: false);
        AssertIndex(
            scimProfile,
            "IX_scimuserprofiles_externalid",
            unique: false,
            "ExternalId");

        var scimGroup = RequiredEntity<ScimGroup>(model);
        Assert.Equal("scimgroups", scimGroup.GetTableName());
        AssertProperty(
            scimGroup,
            "DisplayName",
            "displayname",
            "varchar(256)",
            256,
            nullable: false);
        AssertIndex(
            scimGroup,
            "IX_scimgroups_displayname",
            unique: false,
            "DisplayName");

        var scimUserMember = RequiredEntity<ScimGroupUserMember>(model);
        Assert.Equal("scimgroupusermembers", scimUserMember.GetTableName());
        Assert.Equal(
            ["GroupId", "UserId"],
            scimUserMember.FindPrimaryKey()!.Properties.Select(
                property => property.Name));

        var scimGroupMember = RequiredEntity<ScimGroupGroupMember>(model);
        Assert.Equal("scimgroupgroupmembers", scimGroupMember.GetTableName());
        Assert.Equal(
            ["GroupId", "MemberGroupId"],
            scimGroupMember.FindPrimaryKey()!.Properties.Select(
                property => property.Name));

        // vaultpersonalsecrets is gone: user-typed secrets are now rows in
        // vaultsecrets under the reserved "personal" namespace, so the model
        // must not carry the retired entity any more.
        Assert.DoesNotContain(
            model.GetEntityTypes(),
            entity => entity.GetTableName() == "vaultpersonalsecrets");

        var namedSecret = RequiredEntity<VaultSecret>(model);
        Assert.Equal("vaultsecrets", namedSecret.GetTableName());
        AssertProperty(namedSecret, "ContextId", "contextid", "binary(16)", null, nullable: false);
        AssertProperty(namedSecret, "Namespace", "namespace", "varchar(64)", 64, nullable: false);
        AssertProperty(namedSecret, "Type", "type", "varchar(16)", 16, nullable: false);
        AssertProperty(namedSecret, "OwnerSubject", "ownersubject", "binary(16)", null, nullable: false);
        AssertIndex(namedSecret, "AK_vaultsecrets_context_name", unique: true,
            "Type", "ContextId", "Name");
        AssertIndex(namedSecret, "IX_vaultsecrets_context_namespace", unique: false,
            "Type", "ContextId", "Namespace");
    }

    [Fact]
    public void Migration_history_is_isolated_from_the_legacy_duende_history()
    {
        using var context = CreateContext();

        Assert.Equal([
            IdentityDatabaseSchema.InitialMigrationId,
            IdentityDatabaseSchema.BrandingThemesMigrationId,
            IdentityDatabaseSchema.ManagementAuditMigrationId,
            IdentityDatabaseSchema.ScimProvisioningMigrationId,
            IdentityDatabaseSchema.UserCreatedAtMigrationId,
            IdentityDatabaseSchema.SsfStreamsMigrationId,
            IdentityDatabaseSchema.OidcUserSessionsMigrationId,
            IdentityDatabaseSchema.VaultKeysMigrationId,
            IdentityDatabaseSchema.IdentityApplicationMetricsMigrationId,
            IdentityDatabaseSchema.SsfStreamSecurityMigrationId,
            IdentityDatabaseSchema.AtomicProtocolStateMigrationId,
            IdentityDatabaseSchema.ManagementClientDraftsMigrationId,
            IdentityDatabaseSchema.VaultSecretsMigrationId,
            IdentityDatabaseSchema.VaultSigningKeyJwkMigrationId,
            IdentityDatabaseSchema.VaultPersonalSecretsMigrationId,
            IdentityDatabaseSchema.VaultSigningKeyLifecycleMigrationId,
            IdentityDatabaseSchema.VaultSecretNamespacesMigrationId,
            IdentityDatabaseSchema.BinaryIdentifierCollationMigrationId,
            IdentityDatabaseSchema.VaultSecretExpirationMigrationId,
            IdentityDatabaseSchema.OAuthClientCredentialsMigrationId,
            IdentityDatabaseSchema.ProtocolStateEntriesMigrationId,
            IdentityDatabaseSchema.DropVaultPersonalSecretsMigrationId,
            IdentityDatabaseSchema.VaultSecretTypesMigrationId,
        ], context.Database.GetMigrations());

        var history = context.GetService<IHistoryRepository>().GetCreateScript();
        Assert.Contains($"`{IdentityDatabaseSchema.MigrationsHistoryTable}`", history,
            StringComparison.Ordinal);
        Assert.DoesNotContain("`__efmigrationshistory`", history,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Checked_in_empty_database_script_matches_the_current_migration()
    {
        using var context = CreateContext();
        var generated = context.GetService<IMigrator>().GenerateScript(
            fromMigration: null,
            toMigration: null,
            MigrationsSqlGenerationOptions.Default);

        var tracked = File.ReadAllText(MigrationFile("sql", "001-create-empty-database.sql"));

        Assert.Equal(NormalizeSql(generated), NormalizeSql(tracked));
        Assert.DoesNotContain("\nIF NOT EXISTS(", tracked, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("\nBEGIN\n", tracked, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Legacy_client_migration_preserves_registered_logout_metadata()
    {
        var script = File.ReadAllText(MigrationFile(
            "sql",
            "030-migrate-openiddict-clients.sql"));

        Assert.Contains("c.`frontchannellogouturi`", script, StringComparison.Ordinal);
        Assert.Contains("'frontchannel_logout_uri'", script, StringComparison.Ordinal);
        Assert.Contains("c.`frontchannellogoutsessionrequired`", script, StringComparison.Ordinal);
        Assert.Contains("'frontchannel_logout_session_required'", script, StringComparison.Ordinal);
        Assert.Contains("c.`backchannellogouturi`", script, StringComparison.Ordinal);
        Assert.Contains("'backchannel_logout_uri'", script, StringComparison.Ordinal);
        Assert.Contains("c.`backchannellogoutsessionrequired`", script, StringComparison.Ordinal);
        Assert.Contains("'backchannel_logout_session_required'", script, StringComparison.Ordinal);
        Assert.Contains("JSON_MERGE_PATCH", script, StringComparison.Ordinal);

        // Duende stores Base64(SHA-256), while OpenIddict hashes client
        // secrets with its versioned PBKDF2 format. Copying the legacy value
        // makes every confidential client fail with invalid_client.
        Assert.Contains("Os segredos devem ser reidratados", script,
            StringComparison.Ordinal);
        Assert.Contains("helpers/rehash-openiddict-client-secret.py", script,
            StringComparison.Ordinal);
        Assert.DoesNotContain("SELECT `value` FROM `identity`.`clientsecrets`",
            script, StringComparison.Ordinal);
    }

    [Fact]
    public void Legacy_path_is_additive_and_preflight_is_read_only()
    {
        var fixture = File.ReadAllText(
            MigrationFile("fixtures", "legacy-schema-mariadb-10.4.sql"));
        var preflight = File.ReadAllText(MigrationFile("sql", "010-preflight-legacy.sql"));
        var additive = File.ReadAllText(MigrationFile("sql", "011-add-openiddict-to-legacy.sql"));

        Assert.Equal(39,
            Regex.Matches(fixture, @"(?im)^\s*CREATE TABLE `([^`]+)`").Count);
        Assert.DoesNotMatch(
            new Regex(
                @"(?im)^\s*(INSERT|REPLACE|UPDATE|DELETE|CREATE\s+(VIEW|TRIGGER|PROCEDURE|FUNCTION|EVENT)|LOCK\s+TABLES|USE|CREATE\s+DATABASE)\b"),
            fixture);
        Assert.DoesNotContain("DEFINER=", fixture, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotMatch(new Regex(@"(?i)\bAUTO_INCREMENT=\d+"), fixture);
        Assert.Contains("SET FOREIGN_KEY_CHECKS=0;", fixture,
            StringComparison.Ordinal);
        Assert.EndsWith("SET FOREIGN_KEY_CHECKS=1;", fixture.Trim(),
            StringComparison.Ordinal);

        Assert.DoesNotMatch(
            new Regex(@"(?im)^\s*(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE)\s+"),
            preflight);

        var createdTables = Regex.Matches(additive, @"(?im)^\s*CREATE TABLE `([^`]+)`")
            .Select(match => match.Groups[1].Value)
            .ToArray();

        Assert.Equal([
            IdentityDatabaseSchema.MigrationsHistoryTable,
            "applications",
            "scopes",
            "authorizations",
            "tokens",
        ], createdTables);

        foreach (var sharedTable in new[]
                 {
                     "users", "roles", "roleclaims", "userclaims", "userlogins",
                     "userroles", "usertokens", "userpasskeys", "dataprotectionkeys",
                 })
        {
            Assert.DoesNotContain($"CREATE TABLE `{sharedTable}`", additive,
                StringComparison.OrdinalIgnoreCase);
        }

        Assert.Contains($"('{IdentityDatabaseSchema.InitialMigrationId}', '10.0.10')", additive,
            StringComparison.Ordinal);
        Assert.DoesNotContain("CREATE TABLE IF NOT EXISTS", additive,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Legacy_reference_token_transition_preserves_only_revoked_identifiers()
    {
        var transition = File.ReadAllText(
            MigrationFile("sql", "012-preserve-legacy-reference-token-identifiers.sql"));

        Assert.Contains("FROM `persistedgrants`", transition, StringComparison.Ordinal);
        Assert.Contains("legacy.`type` = 'reference_token'", transition,
            StringComparison.Ordinal);
        Assert.Contains("'revoked'", transition, StringComparison.Ordinal);
        Assert.Contains("'legacy_reference_token'", transition, StringComparison.Ordinal);
        Assert.Contains("'requiresRegeneration', TRUE", transition,
            StringComparison.Ordinal);
        Assert.Contains("'urn:sufficit:token:client_id'", transition,
            StringComparison.Ordinal);
        Assert.Contains("'urn:sufficit:token:description'", transition,
            StringComparison.Ordinal);
        Assert.Contains("`payload` = NULL", transition, StringComparison.Ordinal);
        Assert.DoesNotContain("legacy.`data`", transition, StringComparison.Ordinal);
        Assert.DoesNotContain("legacy.`sessionid`", transition, StringComparison.Ordinal);
        Assert.Contains("UPDATE `persistedgrants`", transition,
            StringComparison.Ordinal);
        Assert.Contains("`consumedtime` = COALESCE", transition,
            StringComparison.Ordinal);
        Assert.Contains("'[identity-upgrade] '", transition,
            StringComparison.Ordinal);
        Assert.DoesNotMatch(
            new Regex(@"(?im)^\s*(DELETE|TRUNCATE|DROP|ALTER)\s+`?persistedgrants`?"),
            transition);
    }

    private static AppDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseMySql(
                "server=localhost;database=identity_contract;user=contract",
                new MariaDbServerVersion(
                    new Version(10, 4, 34)),
                mysql => mysql.MigrationsHistoryTable(IdentityDatabaseSchema.MigrationsHistoryTable))
            .Options;

        return new AppDbContext(options);
    }

    private static IEntityType RequiredEntity<TEntity>(IModel model)
        where TEntity : class =>
        model.FindEntityType(typeof(TEntity))
        ?? throw new InvalidOperationException($"Entity {typeof(TEntity).Name} was not mapped.");

    private static void AssertProperty(
        IEntityType entity,
        string propertyName,
        string columnName,
        string columnType,
        int? maxLength,
        bool nullable)
    {
        var property = entity.FindProperty(propertyName)
            ?? throw new InvalidOperationException(
                $"Property {entity.DisplayName()}.{propertyName} was not mapped.");

        var table = StoreObjectIdentifier.Table(entity.GetTableName()!, entity.GetSchema());
        Assert.Equal(columnName, property.GetColumnName(table));
        Assert.Equal(columnType, property.GetColumnType());
        Assert.Equal(maxLength, property.GetMaxLength());
        Assert.Equal(nullable, property.IsNullable);
    }

    private static void AssertOwnedColumn(
        IEntityType entity,
        string propertyName,
        string columnName,
        string? columnType = null)
    {
        var property = entity.FindProperty(propertyName)
            ?? throw new InvalidOperationException(
                $"Owned property {entity.DisplayName()}.{propertyName} was not mapped.");

        var table = StoreObjectIdentifier.Table(entity.GetTableName()!, entity.GetSchema());
        Assert.Equal(columnName, property.GetColumnName(table));

        if (columnType is not null)
        {
            Assert.Equal(columnType, property.GetColumnType());
        }
    }

    private static void AssertIndex(
        IEntityType entity,
        string databaseName,
        bool unique,
        params string[] properties)
    {
        var index = entity.GetIndexes().Single(candidate =>
            string.Equals(candidate.GetDatabaseName(), databaseName,
                StringComparison.Ordinal));

        Assert.Equal(properties, index.Properties.Select(property => property.Name));
        Assert.Equal(unique, index.IsUnique);
    }

    private static string MigrationFile(params string[] path)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null &&
               !File.Exists(Path.Combine(directory.FullName, "Sufficit.Identity.sln")))
        {
            directory = directory.Parent;
        }

        if (directory is null)
        {
            throw new DirectoryNotFoundException(
                "Could not locate the Sufficit.Identity repository root.");
        }

        return Path.Combine([
            directory.FullName,
            "docs",
            "migration",
            .. path,
        ]);
    }

    private static string NormalizeSql(string sql) =>
        sql.TrimStart('\uFEFF')
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Trim();
}
