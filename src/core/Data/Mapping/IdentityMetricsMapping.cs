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
internal static class IdentityMetricsMapping
{
        internal static void Apply(ModelBuilder builder)
        {
            builder.Entity<Entities.IdentityMetricsConfiguration>(b =>
            {
                b.ToTable("identitymetricsconfiguration");
                b.HasKey(x => x.Id);
                b.Property(x => x.Id).ValueGeneratedNever();
                b.Property(x => x.Provider)
                    .HasMaxLength(IdentityDatabaseSchema.MetricsProviderLength)
                    .IsRequired();
                b.Property(x => x.Endpoint)
                    .HasMaxLength(IdentityDatabaseSchema.MetricsEndpointLength);
                b.Property(x => x.Database)
                    .HasMaxLength(IdentityDatabaseSchema.MetricsDatabaseLength);
                b.Property(x => x.AuthorizationScheme)
                    .HasMaxLength(IdentityDatabaseSchema.MetricsAuthorizationSchemeLength);
                b.Property(x => x.Username)
                    .HasMaxLength(IdentityDatabaseSchema.MetricsUsernameLength);
                b.Property(x => x.SecretCiphertext).HasColumnType("longtext");
                b.Property(x => x.UpdatedAtUtc).HasColumnType("datetime(6)").IsRequired();
                MappingHelpers.SnakeCaseColumns(b, [
                    ("Id", "id"),
                    ("Enabled", "enabled"),
                    ("RetentionDays", "retentiondays"),
                    ("ExportEnabled", "exportenabled"),
                    ("Provider", "provider"),
                    ("Endpoint", "endpoint"),
                    ("Database", "database"),
                    ("AuthorizationScheme", "authorizationscheme"),
                    ("Username", "username"),
                    ("SecretCiphertext", "secretciphertext"),
                    ("TimeoutSeconds", "timeoutseconds"),
                    ("BatchSize", "batchsize"),
                    ("UpdatedAtUtc", "updatedatutc"),
                ]);
            });

            builder.Entity<Entities.IdentityApplicationUsageEvent>(b =>
            {
                b.ToTable("identityapplicationusageevents");
                b.HasKey(x => x.Id);
                b.Property(x => x.Id).ValueGeneratedOnAdd();
                b.Property(x => x.OccurredAtUtc).HasColumnType("datetime(6)").IsRequired();
                b.Property(x => x.ClientId)
                    .HasMaxLength(IdentityDatabaseSchema.MetricsClientIdLength)
                    .IsRequired();
                b.Property(x => x.EventType)
                    .HasMaxLength(IdentityDatabaseSchema.MetricsEventTypeLength)
                    .IsRequired();
                b.Property(x => x.EndpointType)
                    .HasMaxLength(IdentityDatabaseSchema.MetricsEndpointTypeLength)
                    .IsRequired();
                b.Property(x => x.GrantType)
                    .HasMaxLength(IdentityDatabaseSchema.MetricsGrantTypeLength);
                b.Property(x => x.Outcome)
                    .HasMaxLength(IdentityDatabaseSchema.MetricsOutcomeLength)
                    .IsRequired();
                b.Property(x => x.SubjectHash)
                    .HasMaxLength(IdentityDatabaseSchema.MetricsSubjectHashLength);
                b.HasIndex(x => x.OccurredAtUtc)
                    .HasDatabaseName("IX_identityusage_occurredatutc");
                b.HasIndex(x => new { x.ClientId, x.OccurredAtUtc })
                    .HasDatabaseName("IX_identityusage_clientid_occurredatutc");
                b.HasIndex(x => new { x.EventType, x.OccurredAtUtc })
                    .HasDatabaseName("IX_identityusage_eventtype_occurredatutc");
                MappingHelpers.SnakeCaseColumns(b, [
                    ("Id", "id"),
                    ("OccurredAtUtc", "occurredatutc"),
                    ("ClientId", "clientid"),
                    ("EventType", "eventtype"),
                    ("EndpointType", "endpointtype"),
                    ("GrantType", "granttype"),
                    ("Outcome", "outcome"),
                    ("SubjectHash", "subjecthash"),
                ]);
            });
        }
}
