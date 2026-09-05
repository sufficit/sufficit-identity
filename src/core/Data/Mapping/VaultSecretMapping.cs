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
internal static class VaultSecretMapping
{
        internal static void Apply(ModelBuilder builder)
        {
            builder.Entity<Entities.VaultSecret>(b =>
            {
                b.ToTable("vaultsecrets");
                b.HasKey(x => x.Id);
                b.Property(x => x.Id).ValueGeneratedOnAdd();
                b.Property(x => x.Name)
                    .HasMaxLength(IdentityDatabaseSchema.VaultSecretNameLength)
                    .IsRequired();
                b.Property(x => x.Namespace)
                    .HasMaxLength(IdentityDatabaseSchema.VaultSecretNamespaceLength)
                    .IsRequired();
                b.Property(x => x.Type)
                    .HasMaxLength(IdentityDatabaseSchema.VaultSecretTypeLength)
                    .IsRequired();
                b.Property(x => x.ContextId)
                    .HasColumnType("binary(16)")
                    // Explicit Guid↔byte[] conversion pins the .NET ToByteArray
                    // byte order (little-endian first three groups), matching
                    // the storage migration's UNHEX layout and the convention
                    // used across Sufficit databases.
                    .HasConversion<byte[]>()
                    .IsRequired();
                b.Property(x => x.OwnerSubject)
                    .HasColumnType("binary(16)")
                    .HasConversion<byte[]>()
                    .IsRequired();
                b.Property(x => x.Ciphertext)
                    .HasColumnType("longtext")
                    .IsRequired();
                b.Property(x => x.AadJson).HasColumnType("longtext");
                b.Property(x => x.ExpiresAtUtc)
                    .HasColumnType("datetime(6)");
                b.Property(x => x.UpdatedAtUtc)
                    .HasColumnType("datetime(6)")
                    .IsRequired();
                b.Property(x => x.UpdatedBy)
                    .HasMaxLength(IdentityDatabaseSchema.VaultSecretUpdatedByLength)
                    .IsRequired();
                b.HasIndex(x => new { x.Type, x.ContextId, x.Name })
                    .IsUnique()
                    .HasDatabaseName("AK_vaultsecrets_context_name");
                b.HasIndex(x => new { x.Type, x.ContextId, x.Namespace })
                    .HasDatabaseName("IX_vaultsecrets_context_namespace");

                MappingHelpers.SnakeCaseColumns(b, [
                    ("Id", "id"),
                    ("Name", "name"),
                    ("Namespace", "namespace"),
                    ("Type", "type"),
                    ("ContextId", "contextid"),
                    ("OwnerSubject", "ownersubject"),
                    ("Ciphertext", "ciphertext"),
                    ("AadJson", "aadjson"),
                    ("ExpiresAtUtc", "expiresatutc"),
                    ("UpdatedAtUtc", "updatedatutc"),
                    ("UpdatedBy", "updatedby"),
                ]);
            });
        }
}
