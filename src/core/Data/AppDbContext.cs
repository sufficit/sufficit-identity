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
        IdentityUserToken<string>, IdentityUserPasskey<string>>, IDataProtectionKeyContext
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

    /// <summary>
    /// Branding themes for the Sufficit Identity UI. Only one record should
    /// have IsActive = true. Cached by <c>BrandingThemeProvider</c>.
    /// </summary>
    public DbSet<Entities.BrandingTheme> BrandingThemes => Set<Entities.BrandingTheme>();

    /// <summary>
    /// Append-only administrative authorization and mutation audit trail.
    /// </summary>
    public DbSet<Entities.ManagementAuditEvent> ManagementAuditEvents =>
        Set<Entities.ManagementAuditEvent>();

    public DbSet<Entities.ScimUserProfile> ScimUserProfiles =>
        Set<Entities.ScimUserProfile>();

    public DbSet<Entities.ScimGroup> ScimGroups =>
        Set<Entities.ScimGroup>();

    public DbSet<Entities.ScimGroupUserMember> ScimGroupUserMembers =>
        Set<Entities.ScimGroupUserMember>();

    public DbSet<Entities.ScimGroupGroupMember> ScimGroupGroupMembers =>
        Set<Entities.ScimGroupGroupMember>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        MapIdentityTables(builder);
        MapOpenIddictTables(builder);
        MapDataProtectionTable(builder);
        ConfigurePasskeyEntities(builder);
        MapBrandingTables(builder);
        MapManagementAuditTables(builder);
        MapScimTables(builder);
    }

    private static void MapScimTables(ModelBuilder builder)
    {
        builder.Entity<Entities.ScimUserProfile>(b =>
        {
            b.ToTable("scimuserprofiles");
            b.HasKey(x => x.UserId);
            b.Property(x => x.UserId)
                .HasMaxLength(IdentityDatabaseSchema.ScimIdentifierLength);
            b.Property(x => x.ExternalId)
                .HasMaxLength(IdentityDatabaseSchema.ScimIdentifierLength);
            b.Property(x => x.DisplayName)
                .HasMaxLength(IdentityDatabaseSchema.ScimDisplayNameLength);
            b.Property(x => x.FormattedName)
                .HasMaxLength(IdentityDatabaseSchema.ScimDisplayNameLength);
            b.Property(x => x.FamilyName)
                .HasMaxLength(IdentityDatabaseSchema.ScimProfileValueLength);
            b.Property(x => x.GivenName)
                .HasMaxLength(IdentityDatabaseSchema.ScimProfileValueLength);
            b.Property(x => x.MiddleName)
                .HasMaxLength(IdentityDatabaseSchema.ScimProfileValueLength);
            b.Property(x => x.HonorificPrefix)
                .HasMaxLength(IdentityDatabaseSchema.ScimProfileValueLength);
            b.Property(x => x.HonorificSuffix)
                .HasMaxLength(IdentityDatabaseSchema.ScimProfileValueLength);
            b.Property(x => x.Title)
                .HasMaxLength(IdentityDatabaseSchema.ScimProfileValueLength);
            b.Property(x => x.UserType)
                .HasMaxLength(IdentityDatabaseSchema.ScimProfileValueLength);
            b.Property(x => x.PreferredLanguage)
                .HasMaxLength(IdentityDatabaseSchema.ScimLanguageLength);
            b.Property(x => x.Locale)
                .HasMaxLength(IdentityDatabaseSchema.ScimLanguageLength);
            b.Property(x => x.Timezone)
                .HasMaxLength(IdentityDatabaseSchema.ScimTimezoneLength);
            b.HasOne(x => x.User)
                .WithOne()
                .HasForeignKey<Entities.ScimUserProfile>(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            b.HasIndex(x => x.ExternalId)
                .HasDatabaseName("IX_scimuserprofiles_externalid");
            SnakeCaseColumns(b, [
                ("UserId", "userid"),
                ("ExternalId", "externalid"),
                ("DisplayName", "displayname"),
                ("FormattedName", "formattedname"),
                ("FamilyName", "familyname"),
                ("GivenName", "givenname"),
                ("MiddleName", "middlename"),
                ("HonorificPrefix", "honorificprefix"),
                ("HonorificSuffix", "honorificsuffix"),
                ("Title", "title"),
                ("UserType", "usertype"),
                ("PreferredLanguage", "preferredlanguage"),
                ("Locale", "locale"),
                ("Timezone", "timezone"),
                ("CreatedAtUtc", "createdatutc"),
                ("UpdatedAtUtc", "updatedatutc"),
            ]);
        });

        builder.Entity<Entities.ScimGroup>(b =>
        {
            b.ToTable("scimgroups");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id)
                .HasMaxLength(IdentityDatabaseSchema.ScimIdentifierLength);
            b.Property(x => x.ExternalId)
                .HasMaxLength(IdentityDatabaseSchema.ScimIdentifierLength);
            b.Property(x => x.DisplayName)
                .HasMaxLength(IdentityDatabaseSchema.ScimDisplayNameLength)
                .IsRequired();
            b.Property(x => x.ConcurrencyStamp)
                .HasMaxLength(IdentityDatabaseSchema.ScimConcurrencyStampLength)
                .IsRequired();
            b.HasIndex(x => x.ExternalId)
                .HasDatabaseName("IX_scimgroups_externalid");
            b.HasIndex(x => x.DisplayName)
                .HasDatabaseName("IX_scimgroups_displayname");
            SnakeCaseColumns(b, [
                ("Id", "id"),
                ("ExternalId", "externalid"),
                ("DisplayName", "displayname"),
                ("CreatedAtUtc", "createdatutc"),
                ("UpdatedAtUtc", "updatedatutc"),
                ("ConcurrencyStamp", "concurrencystamp"),
            ]);
        });

        builder.Entity<Entities.ScimGroupUserMember>(b =>
        {
            b.ToTable("scimgroupusermembers");
            b.HasKey(x => new { x.GroupId, x.UserId });
            b.Property(x => x.GroupId)
                .HasMaxLength(IdentityDatabaseSchema.ScimIdentifierLength);
            b.Property(x => x.UserId)
                .HasMaxLength(IdentityDatabaseSchema.ScimIdentifierLength);
            b.HasOne(x => x.Group)
                .WithMany(x => x.UserMembers)
                .HasForeignKey(x => x.GroupId)
                .OnDelete(DeleteBehavior.Cascade);
            b.HasOne(x => x.User)
                .WithMany()
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            b.HasIndex(x => x.UserId)
                .HasDatabaseName("IX_scimgroupusermembers_userid");
            SnakeCaseColumns(b, [
                ("GroupId", "groupid"),
                ("UserId", "userid"),
            ]);
        });

        builder.Entity<Entities.ScimGroupGroupMember>(b =>
        {
            b.ToTable("scimgroupgroupmembers");
            b.HasKey(x => new { x.GroupId, x.MemberGroupId });
            b.Property(x => x.GroupId)
                .HasMaxLength(IdentityDatabaseSchema.ScimIdentifierLength);
            b.Property(x => x.MemberGroupId)
                .HasMaxLength(IdentityDatabaseSchema.ScimIdentifierLength);
            b.HasOne(x => x.Group)
                .WithMany(x => x.GroupMembers)
                .HasForeignKey(x => x.GroupId)
                .OnDelete(DeleteBehavior.Cascade);
            b.HasOne(x => x.MemberGroup)
                .WithMany()
                .HasForeignKey(x => x.MemberGroupId)
                .OnDelete(DeleteBehavior.Restrict);
            b.HasIndex(x => x.MemberGroupId)
                .HasDatabaseName("IX_scimgroupgroupmembers_membergroupid");
            SnakeCaseColumns(b, [
                ("GroupId", "groupid"),
                ("MemberGroupId", "membergroupid"),
            ]);
        });
    }

    private static void MapManagementAuditTables(ModelBuilder builder)
    {
        builder.Entity<Entities.ManagementAuditEvent>(b =>
        {
            b.ToTable("managementauditevents");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedOnAdd();
            b.Property(x => x.OccurredAtUtc).IsRequired();
            b.Property(x => x.OperatorSubject)
                .HasMaxLength(IdentityDatabaseSchema.AuditOperatorLength)
                .IsRequired();
            b.Property(x => x.OperatorDisplayName)
                .HasMaxLength(IdentityDatabaseSchema.AuditOperatorLength);
            b.Property(x => x.Capability)
                .HasMaxLength(IdentityDatabaseSchema.AuditCapabilityLength)
                .IsRequired();
            b.Property(x => x.ResourceType)
                .HasMaxLength(IdentityDatabaseSchema.AuditResourceTypeLength)
                .IsRequired();
            b.Property(x => x.ResourceId)
                .HasMaxLength(IdentityDatabaseSchema.AuditResourceIdLength);
            b.Property(x => x.ContextId)
                .HasMaxLength(IdentityDatabaseSchema.AuditResourceIdLength);
            b.Property(x => x.AuthorizationOutcome)
                .HasMaxLength(IdentityDatabaseSchema.AuditOutcomeLength)
                .IsRequired();
            b.Property(x => x.OperationOutcome)
                .HasMaxLength(IdentityDatabaseSchema.AuditOutcomeLength)
                .IsRequired();
            b.Property(x => x.ReasonCode)
                .HasMaxLength(IdentityDatabaseSchema.AuditReasonLength);
            b.Property(x => x.CorrelationId)
                .HasMaxLength(IdentityDatabaseSchema.AuditCorrelationLength)
                .IsRequired();
            b.Property(x => x.AuthenticationMethods)
                .HasMaxLength(IdentityDatabaseSchema.AuditAuthenticationMethodsLength);
            b.HasIndex(x => x.OccurredAtUtc)
                .HasDatabaseName("IX_managementauditevents_occurredatutc");
            b.HasIndex(x => new { x.ResourceType, x.ResourceId })
                .HasDatabaseName("IX_managementauditevents_resource");
            SnakeCaseColumns(b, [
                ("Id", "id"),
                ("OccurredAtUtc", "occurredatutc"),
                ("OperatorSubject", "operatorsubject"),
                ("OperatorDisplayName", "operatordisplayname"),
                ("Capability", "capability"),
                ("ResourceType", "resourcetype"),
                ("ResourceId", "resourceid"),
                ("ContextId", "contextid"),
                ("AuthorizationOutcome", "authorizationoutcome"),
                ("OperationOutcome", "operationoutcome"),
                ("ReasonCode", "reasoncode"),
                ("CorrelationId", "correlationid"),
                ("AuthenticationMethods", "authenticationmethods"),
            ]);
        });
    }

    private static void MapBrandingTables(ModelBuilder builder)
    {
        builder.Entity<Entities.BrandingTheme>(b =>
        {
            b.ToTable("brandingthemes");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedOnAdd();
            b.Property(x => x.Name).HasMaxLength(IdentityDatabaseSchema.BrandingNameLength).IsRequired();
            b.Property(x => x.IsActive).IsRequired();
            b.Property(x => x.LogoUrl).HasMaxLength(IdentityDatabaseSchema.BrandingUrlLength);
            b.Property(x => x.FaviconUrl).HasMaxLength(IdentityDatabaseSchema.BrandingUrlLength);
            b.Property(x => x.HeaderIconUrl).HasMaxLength(IdentityDatabaseSchema.BrandingUrlLength);
            b.Property(x => x.BackgroundImageUrl).HasMaxLength(IdentityDatabaseSchema.BrandingUrlLength);
            b.Property(x => x.BrandColor).HasMaxLength(IdentityDatabaseSchema.BrandingColorLength);
            b.Property(x => x.BrandHoverColor).HasMaxLength(IdentityDatabaseSchema.BrandingColorLength);
            b.Property(x => x.BrandSoftColor).HasMaxLength(IdentityDatabaseSchema.BrandingColorLength);
            b.Property(x => x.ThemeColor).HasMaxLength(IdentityDatabaseSchema.BrandingColorLength);
            b.Property(x => x.Title).HasMaxLength(IdentityDatabaseSchema.BrandingTitleLength);
            b.Property(x => x.BrandName).HasMaxLength(IdentityDatabaseSchema.BrandingNameLength);
            b.Property(x => x.BrandSubtitle).HasMaxLength(IdentityDatabaseSchema.BrandingNameLength);
            b.Property(x => x.AvatarUrlTemplate).HasMaxLength(IdentityDatabaseSchema.BrandingUrlLength);
            b.Property(x => x.CreatedAt).IsRequired();
            b.Property(x => x.UpdatedAt).IsRequired();
            b.HasIndex(x => x.IsActive).HasDatabaseName("IX_brandingthemes_isactive");
            SnakeCaseColumns(b, [
                ("Id", "id"),
                ("Name", "name"),
                ("IsActive", "isactive"),
                ("LogoUrl", "logourl"),
                ("FaviconUrl", "faviconurl"),
                ("HeaderIconUrl", "headericonurl"),
                ("BackgroundImageUrl", "backgroundimageurl"),
                ("BrandColor", "brandcolor"),
                ("BrandHoverColor", "brandhovercolor"),
                ("BrandSoftColor", "brandsoftcolor"),
                ("ThemeColor", "themecolor"),
                ("Title", "title"),
                ("BrandName", "brandname"),
                ("BrandSubtitle", "brandsubtitle"),
                ("AvatarUrlTemplate", "avatarurltemplate"),
                ("CreatedAt", "createdat"),
                ("UpdatedAt", "updatedat"),
            ]);
        });
    }

    /// <summary>
    /// Configura as entidades de passkey do .NET 10 Identity.
    /// O IdentityDbContext base registra <see cref="IdentityUserPasskey{TKey}"/>
    /// como entidade, mas a navigation <c>Data</c> (do tipo
    /// <see cref="IdentityPasskeyData"/>) não é configurada automaticamente
    /// como owned type em todos os cenários (especialmente com TUser customizado
    /// e chave string). Aqui declaramos explicitamente OwnsOne para resolver.
    /// </summary>
    private static void ConfigurePasskeyEntities(ModelBuilder builder)
    {
        builder.Entity<IdentityUserPasskey<string>>(b =>
        {
            b.ToTable("userpasskeys");
            b.Property(p => p.UserId).HasColumnName("userid");
            b.Property(p => p.UserId).IsRequired();
            b.Property(p => p.CredentialId)
                .HasColumnName("credentialid")
                .HasMaxLength(IdentityDatabaseSchema.PasskeyCredentialIdLength);

            // This is the .NET 10 Identity schema already present in the
            // production database: credentialid is globally unique and
            // userid is a lookup index. Do not replace this with a composite
            // key; doing so makes the generated migration diverge from the
            // existing shared Identity tables.
            b.HasKey(p => p.CredentialId);
            b.HasIndex(p => p.UserId).HasDatabaseName("IX_userpasskeys_userid");

            // Data is an owned type stored inline. Every property is mapped
            // explicitly because the default owned-property names use a
            // "Data_" prefix while the established schema uses flat names.
            b.OwnsOne(p => p.Data, d =>
            {
                d.Property(p => p.PublicKey).HasColumnName("publickey");
                d.Property(p => p.Name).HasColumnName("name");
                d.Property(p => p.CreatedAt)
                    .HasColumnName("createdat")
                    .HasColumnType("datetime(6)");
                d.Property(p => p.SignCount).HasColumnName("signcount");
                d.Property(p => p.IsUserVerified).HasColumnName("isuserverified");
                d.Property(p => p.IsBackupEligible).HasColumnName("isbackupeligible");
                d.Property(p => p.IsBackedUp).HasColumnName("isbackedup");
                d.Property(p => p.AttestationObject).HasColumnName("attestationobject");
                d.Property(p => p.ClientDataJson).HasColumnName("clientdatajson");

                // Transports is a string[] and therefore needs a stable JSON
                // representation for a relational string column.
                d.Property(p => p.Transports)
                    .HasColumnName("transports")
                    .IsRequired()
                    .HasConversion(
                        v => v == null ? null : System.Text.Json.JsonSerializer.Serialize(v, (System.Text.Json.JsonSerializerOptions?)null),
                        v => v == null ? Array.Empty<string>() : System.Text.Json.JsonSerializer.Deserialize<string[]>(v, (System.Text.Json.JsonSerializerOptions?)null) ?? Array.Empty<string>())
                    .Metadata.SetValueComparer(
                        new Microsoft.EntityFrameworkCore.ChangeTracking.ValueComparer<string[]>(
                            (a, c) => (a == null && c == null) || (a != null && c != null && a.SequenceEqual(c)),
                            v => v == null ? 0 : v.GetHashCode(),
                            v => v == null ? Array.Empty<string>() : v.ToArray()));
            });
        });
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
            SnakeCaseColumns(b, [
                ("Id", "id"),
                ("UserName", "username"),
                ("NormalizedUserName", "normalizedusername"),
                ("Email", "email"),
                ("NormalizedEmail", "normalizedemail"),
                ("EmailConfirmed", "emailconfirmed"),
                ("PasswordHash", "passwordhash"),
                ("SecurityStamp", "securitystamp"),
                ("ConcurrencyStamp", "concurrencystamp"),
                ("PhoneNumber", "phonenumber"),
                ("PhoneNumberConfirmed", "phonenumberconfirmed"),
                ("TwoFactorEnabled", "twofactorenabled"),
                ("LockoutEnd", "lockoutend"),
                ("LockoutEnabled", "lockoutenabled"),
                ("AccessFailedCount", "accessfailedcount"),
            ]);
            b.Property(u => u.Timestamp)
             .HasColumnName("timestamp")
             .HasColumnType("timestamp")
             // Keep UTC_TIMESTAMP for the existing MariaDB schema semantics.
             // Parentheses also keep the provisional Oracle EF provider from
             // treating this as a literal/default keyword.
             .HasDefaultValueSql("(UTC_TIMESTAMP())")
             .ValueGeneratedOnAddOrUpdate();
            b.Property(u => u.LockoutEnd).HasColumnType("datetime(6)");
        });

        builder.Entity<ApplicationRole>(b =>
        {
            b.ToTable("roles");
            SnakeCaseColumns(b, [
                ("Id", "id"),
                ("Name", "name"),
                ("NormalizedName", "normalizedname"),
                ("ConcurrencyStamp", "concurrencystamp"),
            ]);
        });

        builder.Entity<IdentityUserRole<string>>(b =>
        {
            b.ToTable("userroles");
            SnakeCaseColumns(b, [
                ("UserId", "userid"),
                ("RoleId", "roleid"),
            ]);
        });

        builder.Entity<IdentityUserClaim<string>>(b =>
        {
            b.ToTable("userclaims");
            SnakeCaseColumns(b, [
                ("Id", "id"),
                ("UserId", "userid"),
                ("ClaimType", "claimtype"),
                ("ClaimValue", "claimvalue"),
            ]);
        });

        builder.Entity<IdentityUserLogin<string>>(b =>
        {
            b.ToTable("userlogins");
            SnakeCaseColumns(b, [
                ("LoginProvider", "loginprovider"),
                ("ProviderKey", "providerkey"),
                ("ProviderDisplayName", "providerdisplayname"),
                ("UserId", "userid"),
            ]);
            b.Property(l => l.LoginProvider).HasMaxLength(255);
            b.Property(l => l.ProviderKey).HasMaxLength(255);
        });

        builder.Entity<IdentityUserToken<string>>(b =>
        {
            b.ToTable("usertokens");
            SnakeCaseColumns(b, [
                ("UserId", "userid"),
                ("LoginProvider", "loginprovider"),
                ("Name", "name"),
                ("Value", "value"),
            ]);
            b.Property(t => t.LoginProvider).HasMaxLength(255);
            b.Property(t => t.Name).HasMaxLength(255);
        });

        builder.Entity<IdentityRoleClaim<string>>(b =>
        {
            b.ToTable("roleclaims");
            SnakeCaseColumns(b, [
                ("Id", "id"),
                ("RoleId", "roleid"),
                ("ClaimType", "claimtype"),
                ("ClaimValue", "claimvalue"),
            ]);
        });
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
            b.Property(a => a.Id).HasMaxLength(IdentityDatabaseSchema.OpenIddictKeyLength);
            b.Property(a => a.ApplicationType).HasMaxLength(IdentityDatabaseSchema.OpenIddictShortValueLength);
            b.Property(a => a.ClientId).HasMaxLength(IdentityDatabaseSchema.OpenIddictClientIdLength);
            b.Property(a => a.ClientType).HasMaxLength(IdentityDatabaseSchema.OpenIddictShortValueLength);
            b.Property(a => a.ConcurrencyToken).HasMaxLength(IdentityDatabaseSchema.OpenIddictShortValueLength);
            b.Property(a => a.ConsentType).HasMaxLength(IdentityDatabaseSchema.OpenIddictShortValueLength);
            b.HasIndex(a => a.ClientId)
                .IsUnique()
                .HasDatabaseName("AK_OpenIddictApplications_ClientId");
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
            b.Property(a => a.Id).HasMaxLength(IdentityDatabaseSchema.OpenIddictKeyLength);
            b.Property<string>("ApplicationId").HasMaxLength(IdentityDatabaseSchema.OpenIddictKeyLength);
            b.Property(a => a.ConcurrencyToken).HasMaxLength(IdentityDatabaseSchema.OpenIddictShortValueLength);
            b.Property(a => a.Status).HasMaxLength(IdentityDatabaseSchema.OpenIddictShortValueLength);
            b.Property(a => a.Subject).HasMaxLength(IdentityDatabaseSchema.OpenIddictSubjectLength);
            b.Property(a => a.Type).HasMaxLength(IdentityDatabaseSchema.OpenIddictShortValueLength);
            b.HasIndex("ApplicationId", "Status", "Subject", "Type")
                .HasDatabaseName("IX_OpenIddictAuthorizations_ApplicationId_Status_Subject_Type");
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
            b.Property(s => s.Id).HasMaxLength(IdentityDatabaseSchema.OpenIddictKeyLength);
            b.Property(s => s.ConcurrencyToken).HasMaxLength(IdentityDatabaseSchema.OpenIddictShortValueLength);
            b.Property(s => s.Name).HasMaxLength(IdentityDatabaseSchema.OpenIddictScopeNameLength);
            b.HasIndex(s => s.Name)
                .IsUnique()
                .HasDatabaseName("AK_OpenIddictScopes_Name");
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
            b.Property(t => t.Id).HasMaxLength(IdentityDatabaseSchema.OpenIddictKeyLength);
            b.Property<string>("ApplicationId").HasMaxLength(IdentityDatabaseSchema.OpenIddictKeyLength);
            b.Property<string>("AuthorizationId").HasMaxLength(IdentityDatabaseSchema.OpenIddictKeyLength);
            b.Property(t => t.ConcurrencyToken).HasMaxLength(IdentityDatabaseSchema.OpenIddictShortValueLength);
            b.Property(t => t.ReferenceId).HasMaxLength(IdentityDatabaseSchema.OpenIddictKeyLength);
            b.Property(t => t.Status).HasMaxLength(IdentityDatabaseSchema.OpenIddictShortValueLength);
            b.Property(t => t.Subject).HasMaxLength(IdentityDatabaseSchema.OpenIddictSubjectLength);
            b.Property(t => t.Type).HasMaxLength(IdentityDatabaseSchema.OpenIddictTokenTypeLength);
            b.HasIndex(t => t.ReferenceId)
                .IsUnique()
                .HasDatabaseName("AK_OpenIddictTokens_ReferenceId");
            b.HasIndex("ApplicationId", "Status", "Subject", "Type")
                .HasDatabaseName("IX_OpenIddictTokens_ApplicationId_Status_Subject_Type");
            b.HasIndex("AuthorizationId")
                .HasDatabaseName("IX_OpenIddictTokens_AuthorizationId");
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
        builder.Entity<DataProtectionKey>(b =>
        {
            b.ToTable("dataprotectionkeys");
            SnakeCaseColumns(b, [
                ("Id", "id"),
                ("FriendlyName", "friendlyname"),
                ("Xml", "xml"),
            ]);
        });
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
