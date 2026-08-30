using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Entities;


namespace Sufficit.Identity.Core.Data;

/// <summary>
/// Entity mapping extracted from <see cref="AppDbContext"/>.
/// </summary>
internal static class OpenIddictTablesMapping
{
        /// <summary>
        /// Maps the 4 OpenIddict entities to lowercase snake_case table and
        /// column names (no <c>openiddict_</c> prefix), consistent with the
        /// Sufficit schema convention.
        ///
        /// OpenIddict creates PascalCase names by default
        /// ("OpenIddictApplications", "ClientId", etc). Here we override both
        /// the table name and every column name to snake_case.
        /// </summary>
        internal static void Apply(ModelBuilder builder)
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
                MappingHelpers.SnakeCaseColumns(b, [
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
                MappingHelpers.SnakeCaseColumns(b, [
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
                MappingHelpers.SnakeCaseColumns(b, [
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
                MappingHelpers.SnakeCaseColumns(b, [
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
}
