using System.Data.Common;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class MariaDbMigrationIntegrationTests
{
    private const string ConnectionEnvironmentVariable =
        "SUFFICIT_IDENTITY_MARIADB_CONNECTION";
    private const string RehearsalEnvironmentVariable =
        "SUFFICIT_IDENTITY_ALLOW_EPHEMERAL_DATABASE_REHEARSAL";
    private const string ContractDatabase = "identity_contract";
    private const string RehearsalDatabase = "identity_legacy_rehearsal";

    private static readonly string[] SharedTables =
    [
        "users",
        "roles",
        "roleclaims",
        "userclaims",
        "userlogins",
        "userroles",
        "usertokens",
        "userpasskeys",
        "dataprotectionkeys",
    ];

    [Fact]
    [Trait("Category", "MariaDbIntegration")]
    public async Task Canonical_migration_is_valid_on_the_configured_mariadb_server()
    {
        var connectionString =
            Environment.GetEnvironmentVariable(ConnectionEnvironmentVariable);

        if (string.IsNullOrWhiteSpace(connectionString))
        {
            Assert.False(
                string.Equals(Environment.GetEnvironmentVariable("CI"), "true",
                    StringComparison.OrdinalIgnoreCase),
                $"{ConnectionEnvironmentVariable} is required in CI.");
            return;
        }

        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseMySql(
                connectionString,
                new MariaDbServerVersion(
                    new Version(10, 4, 34)),
                mysql => mysql.MigrationsHistoryTable(
                    IdentityDatabaseSchema.MigrationsHistoryTable))
            .Options;

        await using var context = new AppDbContext(options);

        Assert.True(await context.Database.CanConnectAsync());
        Assert.Empty(await context.Database.GetPendingMigrationsAsync());
        var expectedMigrations = new[]
        {
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
        };
        var appliedMigrations = await context.Database
            .GetAppliedMigrationsAsync();

        // Additive rollout scripts record their own operational markers in the
        // same history table. Compare the EF sequence after filtering those
        // markers, while still requiring every canonical migration in order.
        Assert.Equal(
            expectedMigrations,
            appliedMigrations
                .Where(expectedMigrations.Contains)
                .ToArray());

        await using var connection = context.Database.GetDbConnection();
        await connection.OpenAsync();

        Assert.Equal(35, await ScalarIntAsync(connection, """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
            """));

        Assert.Equal(1, await ScalarIntAsync(connection, """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
              AND table_name = 'oauthclientcredentials'
            """));

        Assert.Equal(1, await ScalarIntAsync(connection, """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
              AND table_name = 'protocolstateentries'
            """));

        Assert.Equal(12, await ScalarIntAsync(connection, $"""
            SELECT COUNT(*)
            FROM `{IdentityDatabaseSchema.MigrationsHistoryTable}`
            WHERE `MigrationId` IN (
                '{IdentityDatabaseSchema.InitialMigrationId}',
                '{IdentityDatabaseSchema.BrandingThemesMigrationId}',
                '{IdentityDatabaseSchema.ManagementAuditMigrationId}',
                '{IdentityDatabaseSchema.ScimProvisioningMigrationId}',
                '{IdentityDatabaseSchema.UserCreatedAtMigrationId}',
                '{IdentityDatabaseSchema.SsfStreamsMigrationId}',
                '{IdentityDatabaseSchema.OidcUserSessionsMigrationId}',
                '{IdentityDatabaseSchema.VaultKeysMigrationId}',
                '{IdentityDatabaseSchema.IdentityApplicationMetricsMigrationId}',
                '{IdentityDatabaseSchema.SsfStreamSecurityMigrationId}',
                '{IdentityDatabaseSchema.AtomicProtocolStateMigrationId}',
                '{IdentityDatabaseSchema.ManagementClientDraftsMigrationId}'
              )
            """));

        Assert.Equal(1, await ScalarIntAsync(connection, """
            SELECT COUNT(*)
            FROM information_schema.statistics
            WHERE table_schema = DATABASE()
              AND table_name = 'applications'
              AND index_name = 'AK_OpenIddictApplications_ClientId'
              AND non_unique = 0
              AND column_name = 'client_id'
            """));

        Assert.Equal(1, await ScalarIntAsync(connection, """
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = 'userpasskeys'
              AND column_name = 'credentialid'
              AND column_type = 'varbinary(1024)'
              AND is_nullable = 'NO'
              AND column_key = 'PRI'
            """));

        Assert.Equal(1, await ScalarIntAsync(connection, """
            SELECT COUNT(*)
            FROM information_schema.statistics
            WHERE table_schema = DATABASE()
              AND table_name = 'brandingthemes'
              AND index_name = 'IX_brandingthemes_isactive'
              AND column_name = 'isactive'
            """));

        Assert.Equal(1, await ScalarIntAsync(connection, """
            SELECT COUNT(*)
            FROM information_schema.statistics
            WHERE table_schema = DATABASE()
              AND table_name = 'managementauditevents'
              AND index_name = 'IX_managementauditevents_resource'
              AND column_name = 'resourceid'
            """));

        Assert.Equal(1, await ScalarIntAsync(connection, """
            SELECT COUNT(*)
            FROM information_schema.statistics
            WHERE table_schema = DATABASE()
              AND table_name = 'scimgroupusermembers'
              AND index_name = 'IX_scimgroupusermembers_userid'
              AND column_name = 'userid'
            """));

        Assert.Equal(1, await ScalarIntAsync(connection, """
            SELECT COUNT(*)
            FROM information_schema.statistics
            WHERE table_schema = DATABASE()
              AND table_name = 'users'
              AND index_name = 'IX_users_createdatutc'
              AND column_name = 'createdatutc'
            """));
    }

    [Fact]
    [Trait("Category", "MariaDbIntegration")]
    public async Task Additive_script_upgrades_the_exact_legacy_schema_without_changing_shared_tables()
    {
        var connectionString =
            Environment.GetEnvironmentVariable(ConnectionEnvironmentVariable);

        if (string.IsNullOrWhiteSpace(connectionString))
        {
            Assert.False(IsContinuousIntegration(),
                $"{ConnectionEnvironmentVariable} is required in CI.");
            return;
        }

        if (!string.Equals(
                Environment.GetEnvironmentVariable(RehearsalEnvironmentVariable),
                "true",
                StringComparison.OrdinalIgnoreCase))
        {
            Assert.False(IsContinuousIntegration(),
                $"{RehearsalEnvironmentVariable}=true is required in CI.");
            return;
        }

        var source = new DbConnectionStringBuilder
        {
            ConnectionString = connectionString,
        };

        Assert.Equal(ContractDatabase, GetConnectionValue(source, "database"));
        Assert.Contains(
            GetConnectionValue(source, "server"),
            new[] { "127.0.0.1", "localhost", "::1" },
            StringComparer.OrdinalIgnoreCase);

        RemoveConnectionValue(source, "database");

        await using var adminContext = CreateContext(source.ConnectionString);
        await using var adminConnection = adminContext.Database.GetDbConnection();
        await adminConnection.OpenAsync();

        await ExecuteNonQueryAsync(adminConnection,
            $"DROP DATABASE IF EXISTS `{RehearsalDatabase}`");
        await ExecuteNonQueryAsync(adminConnection, $"""
            CREATE DATABASE `{RehearsalDatabase}`
                CHARACTER SET utf8mb4
                COLLATE utf8mb4_general_ci
            """);

        try
        {
            source["database"] = RehearsalDatabase;
            await RehearseLegacyMigrationAsync(source.ConnectionString);
        }
        finally
        {
            await ExecuteNonQueryAsync(adminConnection,
                $"DROP DATABASE IF EXISTS `{RehearsalDatabase}`");
        }
    }

    private static async Task RehearseLegacyMigrationAsync(string connectionString)
    {
        await using var context = CreateContext(connectionString);
        await using var connection = context.Database.GetDbConnection();
        await connection.OpenAsync();

        await ExecuteScriptAsync(connection,
            MigrationFile("fixtures", "legacy-schema-mariadb-10.4.sql"));

        Assert.Equal(39, await ScalarIntAsync(connection, """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
              AND table_type = 'BASE TABLE'
            """));

        var preflightIssues = await ReadRowsAsync(
            connection,
            File.ReadAllText(MigrationFile("sql", "010-preflight-legacy.sql")));
        Assert.Empty(preflightIssues);

        var sharedStructureBefore = await SharedStructureAsync(connection);

        await ExecuteScriptAsync(connection,
            MigrationFile("sql", "011-add-openiddict-to-legacy.sql"));

        await ExecuteNonQueryAsync(connection, """
            INSERT INTO `persistedgrants` (
                `key`, `type`, `subjectid`, `clientid`, `creationtime`,
                `expiration`, `data`, `consumedtime`, `description`,
                `sessionid`, `id`
            ) VALUES
                (
                    'LEGACY-REFERENCE-ID-001', 'reference_token',
                    '11111111-1111-1111-1111-111111111111', 'test-client',
                    '2026-01-02 03:04:05.000000', '2026-12-31 23:59:59.000000',
                    '{"secret":"must-not-be-copied"}', NULL, 'test token',
                    'legacy-session', 91001
                ),
                (
                    'LEGACY-REFRESH-ID-IGNORED', 'refresh_token',
                    '11111111-1111-1111-1111-111111111111', 'test-client',
                    '2026-01-02 03:04:05.000000', NULL,
                    '{"secret":"must-not-be-copied"}', NULL, NULL,
                    'legacy-session', 91002
                )
            """);

        await ExecuteScriptAsync(connection,
            MigrationFile("sql", "012-preserve-legacy-reference-token-identifiers.sql"));
        await ExecuteScriptAsync(connection,
            MigrationFile("sql", "012-preserve-legacy-reference-token-identifiers.sql"));

        var sharedStructureAfter = await SharedStructureAsync(connection);
        Assert.Equal(sharedStructureBefore, sharedStructureAfter);

        Assert.Equal(44, await ScalarIntAsync(connection, """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
              AND table_type = 'BASE TABLE'
            """));

        Assert.Equal(4, await ScalarIntAsync(connection, """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
              AND table_name IN ('applications', 'authorizations', 'scopes', 'tokens')
            """));

        Assert.Equal(1, await ScalarIntAsync(connection, $"""
            SELECT COUNT(*)
            FROM `{IdentityDatabaseSchema.MigrationsHistoryTable}`
            WHERE `MigrationId` = '{IdentityDatabaseSchema.InitialMigrationId}'
              AND `ProductVersion` = '10.0.10'
            """));

        Assert.Equal(1, await ScalarIntAsync(connection, """
            SELECT COUNT(*)
            FROM `tokens`
            WHERE `id` = 'legacy-91001'
              AND `reference_id` = 'LEGACY-REFERENCE-ID-001'
              AND `subject` = '11111111-1111-1111-1111-111111111111'
              AND `status` = 'revoked'
              AND `type` = 'legacy_reference_token'
              AND `payload` IS NULL
              AND `redemption_date` IS NOT NULL
              AND JSON_VALUE(`properties`, '$."urn:sufficit:token:client_id"') = 'test-client'
              AND JSON_VALUE(`properties`, '$."urn:sufficit:token:description"') = 'test token'
              AND JSON_VALUE(`properties`, '$."sufficit:migration".requiresRegeneration') = 1
            """));

        Assert.Equal(0, await ScalarIntAsync(connection, """
            SELECT COUNT(*)
            FROM `tokens`
            WHERE `reference_id` = 'LEGACY-REFRESH-ID-IGNORED'
            """));

        Assert.Equal(2, await ScalarIntAsync(connection, """
            SELECT COUNT(*)
            FROM `persistedgrants`
            WHERE `id` IN (91001, 91002)
              AND `data` = '{"secret":"must-not-be-copied"}'
            """));

        Assert.Equal(1, await ScalarIntAsync(connection, """
            SELECT COUNT(*)
            FROM `persistedgrants`
            WHERE `id` = 91001
              AND `type` = 'reference_token'
              AND `consumedtime` IS NOT NULL
              AND `description` = '[identity-upgrade] test token'
            """));

        Assert.Equal(1, await ScalarIntAsync(connection, """
            SELECT COUNT(*)
            FROM `persistedgrants`
            WHERE `id` = 91002
              AND `type` = 'refresh_token'
              AND `consumedtime` IS NULL
            """));
    }

    private static AppDbContext CreateContext(string connectionString)
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseMySql(
                connectionString,
                new MariaDbServerVersion(
                    new Version(10, 4, 34)),
                mysql => mysql.MigrationsHistoryTable(
                    IdentityDatabaseSchema.MigrationsHistoryTable))
            .Options;

        return new AppDbContext(options);
    }

    private static async Task ExecuteScriptAsync(
        DbConnection connection,
        string fileName)
    {
        var script = File.ReadAllText(fileName);
        var statements = Regex.Split(script, @"(?m);\s*(?:\r?\n|$)")
            .Select(statement => statement.Trim())
            .Where(statement => statement.Length > 0);

        foreach (var statement in statements)
        {
            await ExecuteNonQueryAsync(connection, statement);
        }
    }

    private static async Task ExecuteNonQueryAsync(
        DbConnection connection,
        string commandText)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = commandText;
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<string[]> ReadRowsAsync(
        DbConnection connection,
        string commandText)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = commandText;
        await using var reader = await command.ExecuteReaderAsync();
        var rows = new List<string>();

        while (await reader.ReadAsync())
        {
            var row = new string[reader.FieldCount];

            for (var index = 0; index < reader.FieldCount; index++)
            {
                row[index] = reader.IsDBNull(index)
                    ? "<NULL>"
                    : Convert.ToString(
                        reader.GetValue(index),
                        System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
            }

            rows.Add(string.Join('\u001F', row));
        }

        return [.. rows];
    }

    private static async Task<string> SharedStructureAsync(DbConnection connection)
    {
        var tableList = string.Join(", ",
            SharedTables.Select(table => $"'{table}'"));
        var structure = new StringBuilder();

        foreach (var query in new[]
                 {
                     $"""
                      SELECT table_name, ordinal_position, column_name, column_type,
                             is_nullable, column_default, extra, collation_name
                      FROM information_schema.columns
                      WHERE table_schema = DATABASE()
                        AND table_name IN ({tableList})
                      ORDER BY table_name, ordinal_position
                      """,
                     $"""
                      SELECT table_name, index_name, non_unique, seq_in_index,
                             column_name, sub_part, index_type
                      FROM information_schema.statistics
                      WHERE table_schema = DATABASE()
                        AND table_name IN ({tableList})
                      ORDER BY table_name, index_name, seq_in_index
                      """,
                     $"""
                      SELECT table_name, constraint_name, column_name,
                             referenced_table_name, referenced_column_name,
                             ordinal_position
                      FROM information_schema.key_column_usage
                      WHERE table_schema = DATABASE()
                        AND table_name IN ({tableList})
                        AND referenced_table_name IS NOT NULL
                      ORDER BY table_name, constraint_name, ordinal_position
                      """,
                 })
        {
            foreach (var row in await ReadRowsAsync(connection, query))
            {
                structure.AppendLine(row);
            }
        }

        return structure.ToString();
    }

    private static string GetConnectionValue(
        DbConnectionStringBuilder builder,
        string name)
    {
        var key = builder.Keys.Cast<string>().SingleOrDefault(candidate =>
            string.Equals(candidate.Replace(" ", string.Empty, StringComparison.Ordinal),
                name, StringComparison.OrdinalIgnoreCase));

        return key is null
            ? string.Empty
            : Convert.ToString(
                builder[key],
                System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
    }

    private static void RemoveConnectionValue(
        DbConnectionStringBuilder builder,
        string name)
    {
        var key = builder.Keys.Cast<string>().SingleOrDefault(candidate =>
            string.Equals(candidate.Replace(" ", string.Empty, StringComparison.Ordinal),
                name, StringComparison.OrdinalIgnoreCase));

        if (key is not null)
        {
            builder.Remove(key);
        }
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

    private static bool IsContinuousIntegration() =>
        string.Equals(
            Environment.GetEnvironmentVariable("CI"),
            "true",
            StringComparison.OrdinalIgnoreCase);

    private static async Task<int> ScalarIntAsync(
        DbConnection connection,
        string commandText)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = commandText;
        var result = await command.ExecuteScalarAsync();

        return Convert.ToInt32(result, System.Globalization.CultureInfo.InvariantCulture);
    }
}
