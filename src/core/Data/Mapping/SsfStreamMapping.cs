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
internal static class SsfStreamMapping
{
        internal static void Apply(ModelBuilder builder)
        {
            builder.Entity<Entities.SsfStream>(b =>
            {
                b.ToTable("ssfstreams");
                b.HasKey(x => x.Id);
                b.Property(x => x.Id).HasMaxLength(IdentityDatabaseSchema.SsfStreamIdLength);
                b.Property(x => x.StreamId)
                    .HasMaxLength(IdentityDatabaseSchema.SsfStreamIdLength)
                    .IsRequired();
                b.Property(x => x.OwnerClientId)
                    .HasMaxLength(IdentityDatabaseSchema.SsfOwnerClientIdLength);
                b.Property(x => x.Audience)
                    .HasMaxLength(IdentityDatabaseSchema.SsfAudienceLength)
                    .IsRequired();
                b.Property(x => x.DeliveryMethod)
                    .HasMaxLength(IdentityDatabaseSchema.SsfDeliveryMethodLength)
                    .IsRequired();
                b.Property(x => x.Endpoint)
                    .HasMaxLength(IdentityDatabaseSchema.SsfEndpointLength);
                // Authorization stores envelope-encrypted ciphertext (self-describing,
                // AES-256-GCM) when the vault is enabled — longer than the plaintext
                // bearer token. longtext accommodates any token size without a column
                // ceiling that ciphertext could exceed.
                b.Property(x => x.Authorization)
                    .HasColumnType("longtext");
                b.Property(x => x.Status)
                    .HasMaxLength(IdentityDatabaseSchema.SsfStatusLength)
                    .IsRequired();
                b.Property(x => x.VerificationState)
                    .HasMaxLength(IdentityDatabaseSchema.SsfVerificationStateLength)
                    .IsRequired();
                b.Property(x => x.VerificationChallengeHash)
                    .HasMaxLength(IdentityDatabaseSchema.SsfChallengeHashLength);
                b.Property(x => x.VerificationExpiresAtUtc);
                b.Property(x => x.SubjectScope)
                    .HasMaxLength(IdentityDatabaseSchema.SsfScopeLength)
                    .IsRequired();
                b.Property(x => x.EventsRequested)
                    .HasMaxLength(IdentityDatabaseSchema.SsfEventsRequestedLength)
                    .IsRequired();
                b.Property(x => x.Description)
                    .HasMaxLength(IdentityDatabaseSchema.SsfDescriptionLength);
                b.Property(x => x.CreatedAtUtc).IsRequired();
                b.Property(x => x.UpdatedAtUtc).IsRequired();
                b.HasIndex(x => x.StreamId)
                    .IsUnique()
                    .HasDatabaseName("AK_ssfstreams_streamid");
                b.HasIndex(x => x.Status)
                    .HasDatabaseName("IX_ssfstreams_status");
                b.HasIndex(x => new { x.OwnerClientId, x.Status })
                    .HasDatabaseName("IX_ssfstreams_ownerclientid_status");
                MappingHelpers.SnakeCaseColumns(b, [
                    ("Id", "id"),
                    ("StreamId", "streamid"),
                    ("OwnerClientId", "ownerclientid"),
                    ("Audience", "audience"),
                    ("DeliveryMethod", "deliverymethod"),
                    ("Endpoint", "endpoint"),
                    ("Authorization", "authorization"),
                    ("Status", "status"),
                    ("VerificationState", "verificationstate"),
                    ("VerificationChallengeHash", "verificationchallengehash"),
                    ("VerificationExpiresAtUtc", "verificationexpiresatutc"),
                    ("SubjectScope", "subjectscope"),
                    ("EventsRequested", "eventsrequested"),
                    ("Description", "description"),
                    ("CreatedAtUtc", "createdatutc"),
                    ("UpdatedAtUtc", "updatedatutc"),
                ]);
            });

            builder.Entity<Entities.SsfSetDelivery>(b =>
            {
                b.ToTable("ssfsetdeliveries");
                b.HasKey(x => x.Id);
                b.Property(x => x.Id).ValueGeneratedOnAdd();
                b.Property(x => x.StreamId)
                    .HasMaxLength(IdentityDatabaseSchema.SsfStreamIdLength)
                    .IsRequired();
                b.Property(x => x.Jti)
                    .HasMaxLength(IdentityDatabaseSchema.SsfJtiLength)
                    .IsRequired();
                b.Property(x => x.DeliveryKey)
                    .HasMaxLength(IdentityDatabaseSchema.SsfDeliveryKeyLength);
                b.Property(x => x.SetPayload)
                    .HasColumnType("longtext")
                    .IsRequired();
                b.Property(x => x.CreatedAtUtc).IsRequired();
                b.Property(x => x.ConsumedAt);
                b.HasIndex(x => new { x.StreamId, x.ConsumedAt })
                    .HasDatabaseName("IX_ssfsetdeliveries_streamid_consumedat");
                b.HasIndex(x => x.Jti)
                    .HasDatabaseName("IX_ssfsetdeliveries_jti");
                b.HasIndex(x => x.DeliveryKey)
                    .IsUnique()
                    .HasDatabaseName("AK_ssfsetdeliveries_deliverykey");
                MappingHelpers.SnakeCaseColumns(b, [
                    ("Id", "id"),
                    ("StreamId", "streamid"),
                    ("Jti", "jti"),
                    ("DeliveryKey", "deliverykey"),
                    ("SetPayload", "setpayload"),
                    ("CreatedAtUtc", "createdatutc"),
                    ("ConsumedAt", "consumedat"),
                ]);
            });
        }
}
