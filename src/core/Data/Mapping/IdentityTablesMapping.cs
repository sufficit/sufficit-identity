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
internal static class IdentityTablesMapping
{
        /// <summary>
        /// Maps the 8 ASP.NET Core Identity entities to the legacy lowercase
        /// table names already present in the <c>identity2</c> database, so the
        /// existing users/roles/claims load without re-migration.
        /// </summary>
        internal static void Apply(ModelBuilder builder)
        {
            builder.Entity<ApplicationUser>(b =>
            {
                b.ToTable("users");
                MappingHelpers.SnakeCaseColumns(b, [
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
                b.Property(u => u.CreatedAtUtc)
                 .HasColumnName("createdatutc")
                 .HasColumnType("datetime(6)")
                 .HasDefaultValueSql("(UTC_TIMESTAMP(6))")
                 .ValueGeneratedOnAdd();
                b.HasIndex(u => u.CreatedAtUtc)
                 .HasDatabaseName("IX_users_createdatutc");
                b.Property(u => u.LockoutEnd).HasColumnType("datetime(6)");
            });

            builder.Entity<ApplicationRole>(b =>
            {
                b.ToTable("roles");
                MappingHelpers.SnakeCaseColumns(b, [
                    ("Id", "id"),
                    ("Name", "name"),
                    ("NormalizedName", "normalizedname"),
                    ("ConcurrencyStamp", "concurrencystamp"),
                ]);
            });

            builder.Entity<IdentityUserRole<string>>(b =>
            {
                b.ToTable("userroles");
                MappingHelpers.SnakeCaseColumns(b, [
                    ("UserId", "userid"),
                    ("RoleId", "roleid"),
                ]);
            });

            builder.Entity<IdentityUserClaim<string>>(b =>
            {
                b.ToTable("userclaims");
                MappingHelpers.SnakeCaseColumns(b, [
                    ("Id", "id"),
                    ("UserId", "userid"),
                    ("ClaimType", "claimtype"),
                    ("ClaimValue", "claimvalue"),
                ]);
            });

            builder.Entity<IdentityUserLogin<string>>(b =>
            {
                b.ToTable("userlogins");
                MappingHelpers.SnakeCaseColumns(b, [
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
                MappingHelpers.SnakeCaseColumns(b, [
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
                MappingHelpers.SnakeCaseColumns(b, [
                    ("Id", "id"),
                    ("RoleId", "roleid"),
                    ("ClaimType", "claimtype"),
                    ("ClaimValue", "claimvalue"),
                ]);
            });
        }
}
