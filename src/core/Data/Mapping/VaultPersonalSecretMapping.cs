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
internal static class VaultPersonalSecretMapping
{
        internal static void Apply(ModelBuilder builder)
        {
            builder.Entity<Entities.VaultPersonalSecret>(b =>
            {
                b.ToTable("vaultpersonalsecrets");
                b.HasKey(x => x.Id);
                b.Property(x => x.Id).ValueGeneratedOnAdd();
                b.Property(x => x.OwnerSubject)
                    .HasMaxLength(IdentityDatabaseSchema.VaultPersonalSecretOwnerLength)
                    .IsRequired();
                b.Property(x => x.Namespace)
                    .HasMaxLength(IdentityDatabaseSchema.VaultPersonalSecretNamespaceLength)
                    .IsRequired();
                b.Property(x => x.Name)
                    .HasMaxLength(IdentityDatabaseSchema.VaultSecretNameLength)
                    .IsRequired();
                b.Property(x => x.Ciphertext)
                    .HasColumnType("longtext")
                    .IsRequired();
                b.Property(x => x.AadJson).HasColumnType("longtext");
                b.Property(x => x.UpdatedAtUtc)
                    .HasColumnType("datetime(6)")
                    .IsRequired();
                b.Property(x => x.UpdatedBy)
                    .HasMaxLength(IdentityDatabaseSchema.VaultSecretUpdatedByLength)
                    .IsRequired();
                b.HasIndex(x => new { x.OwnerSubject, x.Namespace, x.Name })
                    .IsUnique()
                    .HasDatabaseName("AK_vaultpersonalsecrets_owner_namespace_name");
                b.HasIndex(x => new { x.OwnerSubject, x.Namespace })
                    .HasDatabaseName("IX_vaultpersonalsecrets_owner_namespace");

                MappingHelpers.SnakeCaseColumns(b, [
                    ("Id", "id"),
                    ("OwnerSubject", "ownersubject"),
                    ("Namespace", "namespace"),
                    ("Name", "name"),
                    ("Ciphertext", "ciphertext"),
                    ("AadJson", "aadjson"),
                    ("UpdatedAtUtc", "updatedatutc"),
                    ("UpdatedBy", "updatedby"),
                ]);
            });
        }
}
