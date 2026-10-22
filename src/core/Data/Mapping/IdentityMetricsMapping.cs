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

            builder.Entity<Entities.IdentityApplicationUsageDaily>(b =>
            {
                b.ToTable("identityapplicationusagedaily");
                b.HasKey(x => x.Id);
                b.Property(x => x.Id).ValueGeneratedOnAdd();
                b.Property(x => x.Day).HasColumnType("date").IsRequired();
                b.Property(x => x.Node)
                    .HasMaxLength(IdentityDatabaseSchema.MetricsNodeLength)
                    .IsRequired();
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
                    .HasMaxLength(IdentityDatabaseSchema.MetricsGrantTypeLength)
                    .IsRequired();
                b.Property(x => x.Outcome)
                    .HasMaxLength(IdentityDatabaseSchema.MetricsOutcomeLength)
                    .IsRequired();
                b.Property(x => x.LastOccurredAtUtc).HasColumnType("datetime(6)").IsRequired();
                // One row per day, node and dimension; each node writes only its own.
                b.HasIndex(x => new { x.Day, x.Node, x.ClientId, x.EventType, x.EndpointType, x.GrantType, x.Outcome })
                    .IsUnique()
                    .HasDatabaseName("IX_identityusagedaily_key");
                b.HasIndex(x => new { x.ClientId, x.Day })
                    .HasDatabaseName("IX_identityusagedaily_clientid_day");
                MappingHelpers.SnakeCaseColumns(b, [
                    ("Id", "id"),
                    ("Day", "day"),
                    ("Node", "node"),
                    ("ClientId", "clientid"),
                    ("EventType", "eventtype"),
                    ("EndpointType", "endpointtype"),
                    ("GrantType", "granttype"),
                    ("Outcome", "outcome"),
                    ("Count", "count"),
                    ("LastOccurredAtUtc", "lastoccurredatutc"),
                ]);
            });
        }
}
