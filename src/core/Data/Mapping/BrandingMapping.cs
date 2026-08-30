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
internal static class BrandingMapping
{
        internal static void Apply(ModelBuilder builder)
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
                MappingHelpers.SnakeCaseColumns(b, [
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
}
