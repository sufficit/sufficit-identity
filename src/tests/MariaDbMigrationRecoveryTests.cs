using System.Data;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Sufficit.Identity.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using MySqlConnector;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Server;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class MariaDbMigrationRecoveryTests
{
    [SessionTicketMariaDbOutageTests.LocalMariaDbFact]
    [Trait("Category", "MariaDbIntegration")]
    public async Task Partial_ddl_failure_requires_explicit_repair_before_retry()
    {
        await using var server = new SessionTicketMariaDbOutageTests.LocalMariaDb();
        await server.CreateAsync();
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseMySql(server.ConnectionString, new MariaDbServerVersion(new Version(10, 11)),
                mysql => mysql.MigrationsHistoryTable(IdentityDatabaseSchema.MigrationsHistoryTable))
            .Options;
        await using var db = new AppDbContext(options);
        var migrations = db.Database.GetMigrations().ToArray();
        Assert.Equal(IdentityDatabaseSchema.TokenMaintenanceMigrationId, migrations[^1]);
        await db.GetService<IMigrator>().MigrateAsync(migrations[^2]);
        var before = (await db.Database.GetAppliedMigrationsAsync()).ToArray();

        var user = new ApplicationUser
        {
            Id = "migration-user", UserName = "migration@example.invalid",
            NormalizedUserName = "MIGRATION@EXAMPLE.INVALID",
            Email = "migration@example.invalid", NormalizedEmail = "MIGRATION@EXAMPLE.INVALID",
            EmailConfirmed = true, SecurityStamp = "fixture-security-stamp",
            ConcurrencyStamp = "fixture-user-version", AccessFailedCount = 2,
            LockoutEnabled = true, CreatedAtUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        };
        var hasher = new PasswordHasher<ApplicationUser>();
        user.PasswordHash = hasher.HashPassword(user, "Disposable fixture password 42!");
        db.Users.Add(user);
        db.Roles.Add(new ApplicationRole
        {
            Id = "migration-role", Name = "fixture-role", NormalizedName = "FIXTURE-ROLE",
            ConcurrencyStamp = "fixture-role-version",
        });
        db.UserRoles.Add(new IdentityUserRole<string> { UserId = user.Id, RoleId = "migration-role" });
        db.UserClaims.Add(new IdentityUserClaim<string>
        {
            UserId = user.Id, ClaimType = "fixture-claim", ClaimValue = "opaque-value",
        });
        db.DataProtectionKeys.Add(new DataProtectionKey
        {
            FriendlyName = "migration-fixture", Xml = "<fixture>opaque storage preservation only</fixture>",
        });
        db.Set<OidcUserSession>().Add(new OidcUserSession
        {
            SessionId = "migration-session", Subject = user.Id,
            CreatedAtUtc = user.CreatedAtUtc, LastActivityUtc = user.CreatedAtUtc,
            ProtectedTicket = new byte[] { 0, 1, 127, 128, 255 },
        });
        await db.SaveChangesAsync();
        var dataBefore = await SnapshotAsync(db);

        // This fixture-owned table collides with the SECOND CREATE TABLE in the migration.
        await db.Database.ExecuteSqlRawAsync("CREATE TABLE tokenmaintenanceruns (fixture_marker int NOT NULL)");
        var error = await Assert.ThrowsAsync<MySqlException>(() =>
            HostBootstrap.ApplyMigrationsWithAdvisoryLockAsync(db));
        Assert.Equal(1050, error.Number); // Table already exists.
        Assert.Equal(ConnectionState.Closed, db.Database.GetDbConnection().State);
        Assert.Equal(before, (await db.Database.GetAppliedMigrationsAsync()).ToArray());
        Assert.Equal(dataBefore, await SnapshotAsync(db));
        Assert.Equal(new[] { migrations[^1] }, (await db.Database.GetPendingMigrationsAsync()).ToArray());

        // MariaDB kept the first DDL despite the failed migration: blindly retrying is not repair.
        await using var inspection = new MySqlConnection(server.ConnectionString);
        await inspection.OpenAsync();
        await using var check = inspection.CreateCommand();
        check.CommandText = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'tokenmaintenance'";
        Assert.Equal(1, Convert.ToInt32(await check.ExecuteScalarAsync()));
        check.CommandText = "SELECT COUNT(*) FROM tokenmaintenance";
        Assert.Equal(0, Convert.ToInt32(await check.ExecuteScalarAsync()));
        var retryError = await Assert.ThrowsAsync<MySqlException>(() =>
            HostBootstrap.ApplyMigrationsWithAdvisoryLockAsync(db));
        Assert.Equal(1050, retryError.Number);
        Assert.Equal(before, (await db.Database.GetAppliedMigrationsAsync()).ToArray());
        Assert.Equal(dataBefore, await SnapshotAsync(db));

        // Explicit repair is safe only here: both tables belong to this empty disposable fixture.
        await db.Database.ExecuteSqlRawAsync("DROP TABLE tokenmaintenance, tokenmaintenanceruns");
        await using var recovered = new AppDbContext(options);
        await HostBootstrap.ApplyMigrationsWithAdvisoryLockAsync(recovered);
        Assert.Equal(migrations, (await recovered.Database.GetAppliedMigrationsAsync()).ToArray());
        Assert.Empty(await recovered.Database.GetPendingMigrationsAsync());
        Assert.Equal(dataBefore, await SnapshotAsync(recovered));
        check.CommandText = "SELECT COUNT(*) FROM tokenmaintenance WHERE id = 1 AND enabled = 0 AND revision = 'initial'";
        Assert.Equal(1, Convert.ToInt32(await check.ExecuteScalarAsync()));
        // Completed history makes a subsequent invocation a no-op, preserving the seeded row.
        await HostBootstrap.ApplyMigrationsWithAdvisoryLockAsync(recovered);
        Assert.Equal(migrations, (await recovered.Database.GetAppliedMigrationsAsync()).ToArray());
        Assert.Equal(1, Convert.ToInt32(await check.ExecuteScalarAsync()));
        Assert.Equal(dataBefore, await SnapshotAsync(recovered));
        var preservedUser = await recovered.Users.AsNoTracking().SingleAsync();
        Assert.Equal(PasswordVerificationResult.Success,
            hasher.VerifyHashedPassword(preservedUser, preservedUser.PasswordHash!, "Disposable fixture password 42!"));
    }

    private static async Task<string> SnapshotAsync(AppDbContext db) => JsonSerializer.Serialize(new
    {
        Users = await db.Users.AsNoTracking().OrderBy(x => x.Id).ToArrayAsync(),
        Roles = await db.Roles.AsNoTracking().OrderBy(x => x.Id).ToArrayAsync(),
        Memberships = await db.UserRoles.AsNoTracking().OrderBy(x => x.UserId).ThenBy(x => x.RoleId).ToArrayAsync(),
        Claims = await db.UserClaims.AsNoTracking().OrderBy(x => x.Id).ToArrayAsync(),
        Keys = await db.DataProtectionKeys.AsNoTracking().OrderBy(x => x.Id).ToArrayAsync(),
        Sessions = await db.Set<OidcUserSession>().AsNoTracking().OrderBy(x => x.Id).ToArrayAsync(),
    });
}
