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
internal static class ProtocolSecurityStateMapping
{
        internal static void Apply(ModelBuilder builder)
        {
            builder.Entity<Entities.DpopReplayEntry>(b =>
            {
                b.ToTable("dpopreplayentries");
                b.HasKey(x => x.Key);
                b.Property(x => x.Key)
                    .HasMaxLength(IdentityDatabaseSchema.ProtocolStateKeyLength);
                b.Property(x => x.ExpiresAtUtc).IsRequired();
                b.HasIndex(x => x.ExpiresAtUtc)
                    .HasDatabaseName("IX_dpopreplayentries_expiresatutc");
                MappingHelpers.SnakeCaseColumns(b, [
                    ("Key", "key"),
                    ("ExpiresAtUtc", "expiresatutc"),
                ]);
            });

            builder.Entity<Entities.ProtocolStateEntry>(b =>
            {
                b.ToTable("protocolstateentries");
                b.HasKey(x => x.Key);
                b.Property(x => x.Key)
                    .HasMaxLength(IdentityDatabaseSchema.ProtocolStateKeyLength);
                b.Property(x => x.Purpose)
                    .HasMaxLength(64)
                    .IsRequired();
                b.Property(x => x.Payload).IsRequired();
                b.Property(x => x.ExpiresAtUtc).IsRequired();
                // Expiry sweeps scan by time; purpose narrows a targeted cleanup.
                b.HasIndex(x => x.ExpiresAtUtc)
                    .HasDatabaseName("IX_protocolstateentries_expiresatutc");
                b.HasIndex(x => x.Purpose)
                    .HasDatabaseName("IX_protocolstateentries_purpose");
                MappingHelpers.SnakeCaseColumns(b, [
                    ("Key", "key"),
                    ("Purpose", "purpose"),
                    ("Payload", "payload"),
                    ("ExpiresAtUtc", "expiresatutc"),
                ]);
            });

            builder.Entity<Entities.CibaPendingState>(b =>
            {
                b.ToTable("cibapendingstates");
                b.HasKey(x => x.AuthReqId);
                b.Property(x => x.AuthReqId)
                    .HasMaxLength(IdentityDatabaseSchema.ProtocolStateKeyLength);
                b.Property(x => x.ClientId)
                    .HasMaxLength(IdentityDatabaseSchema.OpenIddictClientIdLength)
                    .IsRequired();
                b.Property(x => x.Subject)
                    .HasMaxLength(IdentityDatabaseSchema.OpenIddictSubjectLength)
                    .IsRequired();
                b.Property(x => x.ScopesJson)
                    .HasMaxLength(IdentityDatabaseSchema.ProtocolStateJsonLength)
                    .IsRequired();
                b.Property(x => x.BindingMessage)
                    .HasMaxLength(IdentityDatabaseSchema.CibaBindingMessageLength);
                b.Property(x => x.ApprovedSubject)
                    .HasMaxLength(IdentityDatabaseSchema.OpenIddictSubjectLength);
                b.Property(x => x.State)
                    .HasMaxLength(IdentityDatabaseSchema.ProtocolStateStatusLength)
                    .IsRequired();
                b.Property(x => x.ConsumptionId)
                    .HasMaxLength(IdentityDatabaseSchema.ProtocolStateKeyLength);
                b.HasIndex(x => new { x.State, x.ExpiresAtUtc })
                    .HasDatabaseName("IX_cibapendingstates_state_expiresatutc");
                b.HasIndex(x => x.ConsumptionId)
                    .IsUnique()
                    .HasDatabaseName("AK_cibapendingstates_consumptionid");
                MappingHelpers.SnakeCaseColumns(b, [
                    ("AuthReqId", "authreqid"),
                    ("ClientId", "clientid"),
                    ("Subject", "subject"),
                    ("ScopesJson", "scopesjson"),
                    ("BindingMessage", "bindingmessage"),
                    ("ExpiresAtUtc", "expiresatutc"),
                    ("CreatedAtUtc", "createdatutc"),
                    ("LastPollAtUtc", "lastpollatutc"),
                    ("ApprovedSubject", "approvedsubject"),
                    ("State", "state"),
                    ("ConsumptionId", "consumptionid"),
                ]);
            });
        }
}
