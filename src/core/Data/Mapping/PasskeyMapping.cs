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
internal static class PasskeyMapping
{
        /// <summary>
        /// Configura as entidades de passkey do .NET 10 Identity.
        /// O IdentityDbContext base registra <see cref="IdentityUserPasskey{TKey}"/>
        /// como entidade, mas a navigation <c>Data</c> (do tipo
        /// <see cref="IdentityPasskeyData"/>) não é configurada automaticamente
        /// como owned type em todos os cenários (especialmente com TUser customizado
        /// e chave string). Aqui declaramos explicitamente OwnsOne para resolver.
        /// </summary>
        internal static void Apply(ModelBuilder builder)
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
}
