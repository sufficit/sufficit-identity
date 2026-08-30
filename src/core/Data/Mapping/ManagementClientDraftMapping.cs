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
internal static class ManagementClientDraftMapping
{
        internal static void Apply(ModelBuilder builder)
        {
            builder.Entity<Entities.ManagementClientDraftRecord>(b =>
            {
                b.ToTable("managementclientdrafts");
                b.HasKey(x => x.Id);
                b.Property(x => x.OwnerSubject)
                    .HasMaxLength(IdentityDatabaseSchema.ManagementDraftOwnerLength)
                    .IsRequired();
                b.Property(x => x.Profile)
                    .HasMaxLength(IdentityDatabaseSchema.ManagementDraftProfileLength)
                    .IsRequired();
                b.Property(x => x.CurrentStep)
                    .HasMaxLength(IdentityDatabaseSchema.ManagementDraftStepLength)
                    .IsRequired();
                b.Property(x => x.Status)
                    .HasMaxLength(IdentityDatabaseSchema.ManagementDraftStatusLength)
                    .IsRequired();
                b.Property(x => x.ProtectedPayload)
                    .HasColumnType("longtext")
                    .IsRequired();
                b.Property(x => x.Version)
                    .HasMaxLength(IdentityDatabaseSchema.ManagementDraftVersionLength)
                    .IsConcurrencyToken()
                    .IsRequired();
                b.Property(x => x.CreatedClientId)
                    .HasMaxLength(IdentityDatabaseSchema.OpenIddictClientIdLength);
                b.Property(x => x.CreatedAtUtc).HasColumnType("datetime(6)").IsRequired();
                b.Property(x => x.UpdatedAtUtc).HasColumnType("datetime(6)").IsRequired();
                b.Property(x => x.ExpiresAtUtc).HasColumnType("datetime(6)").IsRequired();
                b.HasIndex(x => new { x.OwnerSubject, x.Status, x.UpdatedAtUtc })
                    .HasDatabaseName("IX_managementclientdrafts_owner_status_updated");
                b.HasIndex(x => x.ExpiresAtUtc)
                    .HasDatabaseName("IX_managementclientdrafts_expiresatutc");
                MappingHelpers.SnakeCaseColumns(b, [
                    ("Id", "id"),
                    ("OwnerSubject", "ownersubject"),
                    ("Profile", "profile"),
                    ("CurrentStep", "currentstep"),
                    ("Status", "status"),
                    ("ProtectedPayload", "protectedpayload"),
                    ("Version", "version"),
                    ("CreatedClientId", "createdclientid"),
                    ("CreatedAtUtc", "createdatutc"),
                    ("UpdatedAtUtc", "updatedatutc"),
                    ("ExpiresAtUtc", "expiresatutc"),
                ]);
            });
        }
}
