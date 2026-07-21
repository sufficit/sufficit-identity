using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Core.Data;

/// <summary>
/// Unified DbContext for the STS:
///   - ASP.NET Core Identity tables (users, roles, claims, logins, ...)
///   - OpenIddict tables (applications, authorizations, scopes, tokens)
///   - ASP.NET Core Data Protection key ring (dataprotectionkeys)
///
/// All tables and columns follow the Sufficit naming convention:
/// lowercase with underscores (snake_case), no prefixes.
/// </summary>
public sealed class AppDbContext
    : IdentityDbContext<ApplicationUser, ApplicationRole, string,
        IdentityUserClaim<string>, IdentityUserRole<string>,
        IdentityUserLogin<string>, IdentityRoleClaim<string>,
        IdentityUserToken<string>>, IDataProtectionKeyContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    /// <summary>
    /// Backing store for <c>services.AddDataProtection().PersistKeysToDbContext&lt;AppDbContext&gt;()</c>
    /// (see AddSufficitIdentitySTS in ServiceCollectionExtensions.cs, P0 #B4).
    /// Without this, the Data Protection key ring defaults to the local
    /// filesystem, so every container restart or additional replica
    /// regenerates it — invalidating in-flight auth cookies, antiforgery
    /// tokens and ASP.NET Identity reset/confirmation tokens.
    /// </summary>
    public DbSet<DataProtectionKey> DataProtectionKeys { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        MapIdentityTables(builder);
        MapOpenIddictTables(builder);
        MapDataProtectionTable(builder);
    }

    /// <summary>
    /// Maps the 8 ASP.NET Core Identity entities to the legacy lowercase
    /// table names already present in the <c>identity2</c> database, so the
    /// existing users/roles/claims load without re-migration.
    /// </summary>
    private static void MapIdentityTables(ModelBuilder builder)
    {
        builder.Entity<ApplicationUser>(b =>
        {
            b.ToTable("users");
            b.Property(u => u.Timestamp)
             .HasColumnName("timestamp")
             .HasColumnType("timestamp")
             .HasDefaultValueSql("UTC_TIMESTAMP()")
             .ValueGeneratedOnAddOrUpdate();
        });

        builder.Entity<ApplicationRole>(b => b.ToTable("roles"));
        builder.Entity<IdentityUserRole<string>>(b => b.ToTable("userroles"));
        builder.Entity<IdentityUserClaim<string>>(b => b.ToTable("userclaims"));
        builder.Entity<IdentityUserLogin<string>>(b =>
        {
            b.ToTable("userlogins");
            b.Property(l => l.LoginProvider).HasMaxLength(255);
            b.Property(l => l.ProviderKey).HasMaxLength(255);
        });
        builder.Entity<IdentityUserToken<string>>(b =>
        {
            b.ToTable("usertokens");
            b.Property(t => t.LoginProvider).HasMaxLength(255);
            b.Property(t => t.Name).HasMaxLength(255);
        });
        builder.Entity<IdentityRoleClaim<string>>(b => b.ToTable("roleclaims"));
    }

    /// <summary>
    /// Maps the 4 OpenIddict entities to lowercase snake_case table and
    /// column names (no <c>openiddict_</c> prefix), consistent with the
    /// Sufficit schema convention.
    ///
    /// OpenIddict creates PascalCase names by default
    /// ("OpenIddictApplications", "ClientId", etc). Here we override both
    /// the table name and every column name to snake_case.
    /// </summary>
    private static void MapOpenIddictTables(ModelBuilder builder)
    {
        // ---- applications ----
        builder.Entity<OpenIddictEntityFrameworkCoreApplication>(b =>
        {
            b.ToTable("applications");
            SnakeCaseColumns(b, [
                ("Id", "id"),
                ("ApplicationType", "application_type"),
                ("ClientId", "client_id"),
                ("ClientSecret", "client_secret"),
                ("ClientType", "client_type"),
                ("ConcurrencyToken", "concurrency_token"),
                ("ConsentType", "consent_type"),
                ("DisplayName", "display_name"),
                ("DisplayNames", "display_names"),
                ("JsonWebKeySet", "json_web_key_set"),
                ("Permissions", "permissions"),
                ("PostLogoutRedirectUris", "post_logout_redirect_uris"),
                ("Properties", "properties"),
                ("RedirectUris", "redirect_uris"),
                ("Requirements", "requirements"),
                ("Settings", "settings"),
            ]);
        });

        // ---- authorizations ----
        builder.Entity<OpenIddictEntityFrameworkCoreAuthorization>(b =>
        {
            b.ToTable("authorizations");
            SnakeCaseColumns(b, [
                ("Id", "id"),
                ("ApplicationId", "application_id"),
                ("ConcurrencyToken", "concurrency_token"),
                ("CreationDate", "creation_date"),
                ("Properties", "properties"),
                ("Scopes", "scopes"),
                ("Status", "status"),
                ("Subject", "subject"),
                ("Type", "type"),
            ]);
        });

        // ---- scopes ----
        builder.Entity<OpenIddictEntityFrameworkCoreScope>(b =>
        {
            b.ToTable("scopes");
            SnakeCaseColumns(b, [
                ("Id", "id"),
                ("ConcurrencyToken", "concurrency_token"),
                ("Description", "description"),
                ("Descriptions", "descriptions"),
                ("DisplayName", "display_name"),
                ("DisplayNames", "display_names"),
                ("Name", "name"),
                ("Properties", "properties"),
                ("Resources", "resources"),
            ]);
        });

        // ---- tokens ----
        builder.Entity<OpenIddictEntityFrameworkCoreToken>(b =>
        {
            b.ToTable("tokens");
            SnakeCaseColumns(b, [
                ("Id", "id"),
                ("ApplicationId", "application_id"),
                ("AuthorizationId", "authorization_id"),
                ("ConcurrencyToken", "concurrency_token"),
                ("CreationDate", "creation_date"),
                ("ExpirationDate", "expiration_date"),
                ("Payload", "payload"),
                ("Properties", "properties"),
                ("RedemptionDate", "redemption_date"),
                ("ReferenceId", "reference_id"),
                ("Status", "status"),
                ("Subject", "subject"),
                ("Type", "type"),
            ]);
        });
    }

    /// <summary>
    /// Maps the single ASP.NET Core Data Protection key-ring entity
    /// (<c>DataProtectionKey</c>), persisted here via
    /// <c>PersistKeysToDbContext&lt;AppDbContext&gt;()</c> (P0 #B4). Table
    /// name follows the same lowercase-no-separators convention as the
    /// Identity tables above (default PascalCase columns: Id, FriendlyName,
    /// Xml — NOT the snake_case convention used for the OpenIddict tables).
    ///
    /// PRODUCTION SQL RUNBOOK: dev/tests create this table automatically via
    /// <c>Database.EnsureCreatedAsync()</c>; production provisions schema
    /// from manual SQL (docs/migration/sql/*), which MUST add this table
    /// (columns: Id INT PK IDENTITY, FriendlyName TEXT NULL, Xml TEXT/
    /// LONGTEXT NULL) BEFORE deploying this change — reading/writing the
    /// key ring against a schema that predates this table throws (the
    /// query fails with "table doesn't exist"), it does not silently fall
    /// back to an unpersisted key ring.
    /// </summary>
    private static void MapDataProtectionTable(ModelBuilder builder)
    {
        builder.Entity<DataProtectionKey>(b => b.ToTable("dataprotectionkeys"));
    }

    /// <summary>
    /// Applies <c>HasColumnName</c> for each (property, column) pair.
    /// </summary>
    private static void SnakeCaseColumns<T>(EntityTypeBuilder<T> b,
        params (string Property, string Column)[] mappings)
        where T : class
    {
        foreach (var (prop, col) in mappings)
        {
            b.Property(prop).HasColumnName(col);
        }
    }
}
