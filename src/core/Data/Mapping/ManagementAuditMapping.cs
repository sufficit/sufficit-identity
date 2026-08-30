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
internal static class ManagementAuditMapping
{
        internal static void Apply(ModelBuilder builder)
        {
            builder.Entity<Entities.ManagementAuditEvent>(b =>
            {
                b.ToTable("managementauditevents");
                b.HasKey(x => x.Id);
                b.Property(x => x.Id).ValueGeneratedOnAdd();
                b.Property(x => x.OccurredAtUtc).IsRequired();
                b.Property(x => x.OperatorSubject)
                    .HasMaxLength(IdentityDatabaseSchema.AuditOperatorLength)
                    .IsRequired();
                b.Property(x => x.OperatorDisplayName)
                    .HasMaxLength(IdentityDatabaseSchema.AuditOperatorLength);
                b.Property(x => x.Capability)
                    .HasMaxLength(IdentityDatabaseSchema.AuditCapabilityLength)
                    .IsRequired();
                b.Property(x => x.ResourceType)
                    .HasMaxLength(IdentityDatabaseSchema.AuditResourceTypeLength)
                    .IsRequired();
                b.Property(x => x.ResourceId)
                    .HasMaxLength(IdentityDatabaseSchema.AuditResourceIdLength);
                b.Property(x => x.ContextId)
                    .HasMaxLength(IdentityDatabaseSchema.AuditResourceIdLength);
                b.Property(x => x.AuthorizationOutcome)
                    .HasMaxLength(IdentityDatabaseSchema.AuditOutcomeLength)
                    .IsRequired();
                b.Property(x => x.OperationOutcome)
                    .HasMaxLength(IdentityDatabaseSchema.AuditOutcomeLength)
                    .IsRequired();
                b.Property(x => x.ReasonCode)
                    .HasMaxLength(IdentityDatabaseSchema.AuditReasonLength);
                b.Property(x => x.CorrelationId)
                    .HasMaxLength(IdentityDatabaseSchema.AuditCorrelationLength)
                    .IsRequired();
                b.Property(x => x.AuthenticationMethods)
                    .HasMaxLength(IdentityDatabaseSchema.AuditAuthenticationMethodsLength);
                b.HasIndex(x => x.OccurredAtUtc)
                    .HasDatabaseName("IX_managementauditevents_occurredatutc");
                b.HasIndex(x => new { x.ResourceType, x.ResourceId })
                    .HasDatabaseName("IX_managementauditevents_resource");
                MappingHelpers.SnakeCaseColumns(b, [
                    ("Id", "id"),
                    ("OccurredAtUtc", "occurredatutc"),
                    ("OperatorSubject", "operatorsubject"),
                    ("OperatorDisplayName", "operatordisplayname"),
                    ("Capability", "capability"),
                    ("ResourceType", "resourcetype"),
                    ("ResourceId", "resourceid"),
                    ("ContextId", "contextid"),
                    ("AuthorizationOutcome", "authorizationoutcome"),
                    ("OperationOutcome", "operationoutcome"),
                    ("ReasonCode", "reasoncode"),
                    ("CorrelationId", "correlationid"),
                    ("AuthenticationMethods", "authenticationmethods"),
                ]);
            });
        }
}
