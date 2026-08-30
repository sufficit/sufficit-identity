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
internal static class ScimMapping
{
        internal static void Apply(ModelBuilder builder)
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
                MappingHelpers.SnakeCaseColumns(b, [
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
                MappingHelpers.SnakeCaseColumns(b, [
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
                MappingHelpers.SnakeCaseColumns(b, [
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
                MappingHelpers.SnakeCaseColumns(b, [
                    ("GroupId", "groupid"),
                    ("MemberGroupId", "membergroupid"),
                ]);
            });
        }
}
