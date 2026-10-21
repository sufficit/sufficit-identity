using Microsoft.EntityFrameworkCore;

namespace Sufficit.Identity.Core.Data;

internal static class SystemUserMapping
{
    internal static void Apply(ModelBuilder builder)
    {
        builder.Entity<Entities.SystemUser>(b =>
        {
            b.ToTable("systemusers");
            b.HasKey(x => x.UserId);
            b.Property(x => x.UserId)
                .HasMaxLength(IdentityDatabaseSchema.SystemUserSubjectLength)
                .IsRequired();
            b.Property(x => x.CreatedBy)
                .HasMaxLength(IdentityDatabaseSchema.SystemUserSubjectLength)
                .IsRequired();
            b.Property(x => x.CorrelationId)
                .HasMaxLength(IdentityDatabaseSchema.SystemUserCorrelationLength);
            b.Property(x => x.DisabledBy)
                .HasMaxLength(IdentityDatabaseSchema.SystemUserSubjectLength);
            b.Property(x => x.CreatedAtUtc).HasColumnType("datetime(6)").IsRequired();
            b.Property(x => x.DisabledAtUtc).HasColumnType("datetime(6)");
            b.HasOne<Entities.ApplicationUser>()
                .WithOne()
                .HasForeignKey<Entities.SystemUser>(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            MappingHelpers.SnakeCaseColumns(b, [
                ("UserId", "userid"),
                ("CreatedBy", "createdby"),
                ("CreatedAtUtc", "createdatutc"),
                ("CorrelationId", "correlationid"),
                ("DisabledAtUtc", "disabledatutc"),
                ("DisabledBy", "disabledby"),
            ]);
        });

        builder.Entity<Entities.SystemUserEnrollment>(b =>
        {
            b.ToTable("systemuserenrollments");
            b.HasKey(x => x.Id);
            b.Property(x => x.UserId)
                .HasMaxLength(IdentityDatabaseSchema.SystemUserSubjectLength)
                .IsRequired();
            b.Property(x => x.ClientId)
                .HasMaxLength(IdentityDatabaseSchema.SystemUserClientIdLength)
                .IsRequired();
            b.Property(x => x.Label)
                .HasMaxLength(IdentityDatabaseSchema.SystemUserEnrollmentLabelLength)
                .IsRequired();
            b.Property(x => x.CodeHash)
                .HasMaxLength(IdentityDatabaseSchema.SystemUserEnrollmentHashLength)
                .IsRequired();
            b.Property(x => x.CodeHint)
                .HasMaxLength(IdentityDatabaseSchema.SystemUserEnrollmentHintLength)
                .IsRequired();
            b.Property(x => x.IssuedBy)
                .HasMaxLength(IdentityDatabaseSchema.SystemUserSubjectLength)
                .IsRequired();
            b.Property(x => x.AuthorizationId)
                .HasMaxLength(IdentityDatabaseSchema.SystemUserAuthorizationIdLength);
            b.Property(x => x.RevokedBy)
                .HasMaxLength(IdentityDatabaseSchema.SystemUserSubjectLength);
            b.Property(x => x.CreatedAtUtc).HasColumnType("datetime(6)").IsRequired();
            b.Property(x => x.ExpiresAtUtc).HasColumnType("datetime(6)").IsRequired();
            b.Property(x => x.RedeemedAtUtc).HasColumnType("datetime(6)");
            b.Property(x => x.RevokedAtUtc).HasColumnType("datetime(6)");
            b.HasIndex(x => x.CodeHash)
                .IsUnique()
                .HasDatabaseName("IX_systemuserenrollments_codehash");
            b.HasIndex(x => x.UserId)
                .HasDatabaseName("IX_systemuserenrollments_userid");
            b.HasOne<Entities.SystemUser>()
                .WithMany()
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            MappingHelpers.SnakeCaseColumns(b, [
                ("Id", "id"),
                ("UserId", "userid"),
                ("ClientId", "clientid"),
                ("Label", "label"),
                ("CodeHash", "codehash"),
                ("CodeHint", "codehint"),
                ("IssuedBy", "issuedby"),
                ("CreatedAtUtc", "createdatutc"),
                ("ExpiresAtUtc", "expiresatutc"),
                ("RedeemedAtUtc", "redeemedatutc"),
                ("AuthorizationId", "authorizationid"),
                ("RevokedAtUtc", "revokedatutc"),
                ("RevokedBy", "revokedby"),
            ]);
        });
    }
}
