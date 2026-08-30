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
internal static class VaultKeyMapping
{
        /// <summary>
        /// Maps the vault keys table (wrapped DEKs / item keys). Naming follows
        /// the lowercase-no-prefix convention.
        /// </summary>
        internal static void Apply(ModelBuilder builder)
        {
            builder.Entity<Entities.VaultKey>(b =>
            {
                b.ToTable("vaultkeys");
                b.HasKey(x => x.Id);
                b.Property(x => x.Id).ValueGeneratedOnAdd();
                b.Property(x => x.KeyName)
                    .HasMaxLength(IdentityDatabaseSchema.VaultKeyNameLength)
                    .IsRequired();
                b.Property(x => x.KeyVersion).IsRequired();
                b.Property(x => x.Purpose)
                    .HasMaxLength(IdentityDatabaseSchema.VaultPurposeLength)
                    .IsRequired();
                b.Property(x => x.WrappedKey).HasColumnType("longblob").IsRequired();
                b.Property(x => x.PublicJwk).HasColumnType("longtext");
                b.Property(x => x.CreatedAtUtc).HasColumnType("datetime(6)").IsRequired();
                b.Property(x => x.RetiredAtUtc).HasColumnType("datetime(6)");
                b.Property(x => x.SigningState)
                    .HasConversion<string>()
                    .HasMaxLength(IdentityDatabaseSchema.VaultSigningStateLength);
                b.Property(x => x.RetireAfterUtc).HasColumnType("datetime(6)");
                b.Property(x => x.RevokedAtUtc).HasColumnType("datetime(6)");
                b.Property(x => x.LifecycleVersion)
                    .IsRequired()
                    .IsConcurrencyToken();

                b.HasIndex(x => new { x.KeyName, x.KeyVersion })
                    .IsUnique()
                    .HasDatabaseName("AK_vaultkeys_keyname_keyversion");

                MappingHelpers.SnakeCaseColumns(b, [
                    ("Id", "id"),
                    ("KeyName", "keyname"),
                    ("KeyVersion", "keyversion"),
                    ("Purpose", "purpose"),
                    ("WrappedKey", "wrappedkey"),
                    ("PublicJwk", "publicjwk"),
                    ("CreatedAtUtc", "createdatutc"),
                    ("RetiredAtUtc", "retiredatutc"),
                    ("SigningState", "signingstate"),
                    ("RetireAfterUtc", "retireafterutc"),
                    ("RevokedAtUtc", "revokedatutc"),
                    ("LifecycleVersion", "lifecycleversion"),
                ]);
            });

            builder.Entity<Entities.VaultSigningKeyLifecycleOperation>(b =>
            {
                b.ToTable("vaultsigningkeyoperations");
                b.HasKey(x => x.OperationId);
                b.Property(x => x.OperationId)
                    .HasMaxLength(IdentityDatabaseSchema.VaultLifecycleOperationIdLength);
                b.Property(x => x.KeyName)
                    .HasMaxLength(IdentityDatabaseSchema.VaultKeyNameLength)
                    .IsRequired();
                b.Property(x => x.Action)
                    .HasMaxLength(IdentityDatabaseSchema.VaultLifecycleActionLength)
                    .IsRequired();
                b.Property(x => x.Reason)
                    .HasMaxLength(IdentityDatabaseSchema.VaultLifecycleReasonLength);
                b.Property(x => x.OccurredAtUtc).HasColumnType("datetime(6)").IsRequired();
                b.Property(x => x.RetireAfterUtc).HasColumnType("datetime(6)");
                b.HasIndex(x => new { x.KeyName, x.OccurredAtUtc })
                    .HasDatabaseName("IX_vaultsigningkeyoperations_keyname_occurred");
                MappingHelpers.SnakeCaseColumns(b, [
                    ("OperationId", "operationid"),
                    ("KeyName", "keyname"),
                    ("KeyVersion", "keyversion"),
                    ("PreviousKeyVersion", "previouskeyversion"),
                    ("Action", "action"),
                    ("Reason", "reason"),
                    ("OccurredAtUtc", "occurredatutc"),
                    ("RetireAfterUtc", "retireafterutc"),
                ]);
            });

            builder.Entity<Entities.VaultSigningKeyLock>(b =>
            {
                b.ToTable("vaultsigningkeylocks");
                b.HasKey(x => x.KeyName);
                b.Property(x => x.KeyName)
                    .HasMaxLength(IdentityDatabaseSchema.VaultKeyNameLength);
                b.Property(x => x.OwnerId)
                    .HasMaxLength(IdentityDatabaseSchema.VaultLockOwnerLength)
                    .IsRequired();
                b.Property(x => x.ExpiresAtUtc).HasColumnType("datetime(6)").IsRequired();
                MappingHelpers.SnakeCaseColumns(b, [
                    ("KeyName", "keyname"),
                    ("OwnerId", "ownerid"),
                    ("ExpiresAtUtc", "expiresatutc"),
                ]);
            });
        }
}
