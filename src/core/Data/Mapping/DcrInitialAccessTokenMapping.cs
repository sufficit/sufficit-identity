using Microsoft.EntityFrameworkCore;

namespace Sufficit.Identity.Core.Data;

internal static class DcrInitialAccessTokenMapping
{
    internal static void Apply(ModelBuilder builder)
    {
        builder.Entity<Entities.DcrInitialAccessToken>(b =>
        {
            b.ToTable("dcrinitialaccesstokens");
            b.HasKey(x => x.Id);
            b.Property(x => x.Label)
                .HasMaxLength(IdentityDatabaseSchema.DcrInitialAccessTokenLabelLength)
                .IsRequired();
            b.Property(x => x.TokenHash)
                .HasMaxLength(IdentityDatabaseSchema.DcrInitialAccessTokenHashLength)
                .IsRequired();
            b.Property(x => x.TokenHint)
                .HasMaxLength(IdentityDatabaseSchema.DcrInitialAccessTokenHintLength)
                .IsRequired();
            b.Property(x => x.IssuedBy)
                .HasMaxLength(IdentityDatabaseSchema.DcrInitialAccessTokenSubjectLength)
                .IsRequired();
            b.Property(x => x.AllowedGrantTypesJson)
                .HasMaxLength(IdentityDatabaseSchema.DcrInitialAccessTokenPolicyJsonLength);
            b.Property(x => x.AllowedScopesJson)
                .HasMaxLength(IdentityDatabaseSchema.DcrInitialAccessTokenPolicyJsonLength);
            b.Property(x => x.RevokedBy)
                .HasMaxLength(IdentityDatabaseSchema.DcrInitialAccessTokenSubjectLength);
            b.Property(x => x.CreatedAtUtc).HasColumnType("datetime(6)").IsRequired();
            b.Property(x => x.ExpiresAtUtc).HasColumnType("datetime(6)").IsRequired();
            b.Property(x => x.LastUsedAtUtc).HasColumnType("datetime(6)");
            b.Property(x => x.RevokedAtUtc).HasColumnType("datetime(6)");
            b.HasIndex(x => x.TokenHash)
                .IsUnique()
                .HasDatabaseName("IX_dcrinitialaccesstokens_tokenhash");
            b.HasIndex(x => x.ExpiresAtUtc)
                .HasDatabaseName("IX_dcrinitialaccesstokens_expiresatutc");
            MappingHelpers.SnakeCaseColumns(b, [
                ("Id", "id"),
                ("Label", "label"),
                ("TokenHash", "tokenhash"),
                ("TokenHint", "tokenhint"),
                ("IssuedBy", "issuedby"),
                ("CreatedAtUtc", "createdatutc"),
                ("ExpiresAtUtc", "expiresatutc"),
                ("SingleUse", "singleuse"),
                ("RegistrationCount", "registrationcount"),
                ("AllowedGrantTypesJson", "allowedgranttypesjson"),
                ("AllowedScopesJson", "allowedscopesjson"),
                ("LastUsedAtUtc", "lastusedatutc"),
                ("RevokedAtUtc", "revokedatutc"),
                ("RevokedBy", "revokedby"),
            ]);
        });
    }
}
