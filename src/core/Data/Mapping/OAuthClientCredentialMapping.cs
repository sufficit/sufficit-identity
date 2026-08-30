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
internal static class OAuthClientCredentialMapping
{
        internal static void Apply(ModelBuilder builder)
        {
            builder.Entity<Entities.OAuthClientCredential>(b =>
            {
                b.ToTable("oauthclientcredentials");
                b.HasKey(x => x.Id);
                b.Property(x => x.ClientId)
                    .HasMaxLength(IdentityDatabaseSchema.OpenIddictClientIdLength)
                    .IsRequired();
                b.Property(x => x.Kind)
                    .HasMaxLength(IdentityDatabaseSchema.OAuthClientCredentialKindLength)
                    .IsRequired();
                b.Property(x => x.Label)
                    .HasMaxLength(IdentityDatabaseSchema.OAuthClientCredentialLabelLength)
                    .IsRequired();
                b.Property(x => x.SecretHash)
                    .HasMaxLength(IdentityDatabaseSchema.OAuthClientCredentialHashLength)
                    .IsRequired();
                b.Property(x => x.SecretHint)
                    .HasMaxLength(IdentityDatabaseSchema.OAuthClientCredentialHintLength)
                    .IsRequired();
                b.Property(x => x.RevocationReason)
                    .HasMaxLength(IdentityDatabaseSchema.OAuthClientCredentialReasonLength);
                b.Property(x => x.ConcurrencyToken)
                    .HasMaxLength(IdentityDatabaseSchema.OAuthClientCredentialConcurrencyLength)
                    .IsConcurrencyToken()
                    .IsRequired();
                b.Property(x => x.CreatedAtUtc).HasColumnType("datetime(6)").IsRequired();
                b.Property(x => x.NotBeforeUtc).HasColumnType("datetime(6)");
                b.Property(x => x.ExpiresAtUtc).HasColumnType("datetime(6)");
                b.Property(x => x.RevokedAtUtc).HasColumnType("datetime(6)");
                b.HasIndex(x => new { x.ClientId, x.Kind, x.RevokedAtUtc, x.ExpiresAtUtc })
                    .HasDatabaseName("IX_oauthclientcredentials_client_kind_status");
                b.HasIndex(x => x.ExpiresAtUtc)
                    .HasDatabaseName("IX_oauthclientcredentials_expiresatutc");
                MappingHelpers.SnakeCaseColumns(b, [
                    ("Id", "id"),
                    ("ClientId", "clientid"),
                    ("Kind", "kind"),
                    ("Label", "label"),
                    ("SecretHash", "secrethash"),
                    ("SecretHint", "secrethint"),
                    ("CreatedAtUtc", "createdatutc"),
                    ("NotBeforeUtc", "notbeforeutc"),
                    ("ExpiresAtUtc", "expiresatutc"),
                    ("RevokedAtUtc", "revokedatutc"),
                    ("RevocationReason", "revocationreason"),
                    ("ConcurrencyToken", "concurrencytoken"),
                ]);
            });
        }
}
