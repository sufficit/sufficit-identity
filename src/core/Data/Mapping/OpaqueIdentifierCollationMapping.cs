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
internal static class OpaqueIdentifierCollationMapping
{
        /// <summary>
        /// Binary collations for opaque, case-sensitive identifiers (F-3, eval
        /// 2026-08-14). MariaDB defaults every utf8mb4 column to
        /// <c>utf8mb4_general_ci</c>, silently halving the distinguishable
        /// alphabet of base64url/GUID identifiers such as reference tokens, session
        /// ids, CIBA auth_req_ids, SSF stream ids and DPoP replay keys, and making
        /// unique indexes fold case variants together. Keeping the whole list in
        /// one place makes the contract reviewable and covered by the schema
        /// contract tests.
        /// </summary>
        internal static void Apply(ModelBuilder builder)
        {
            builder.Entity<OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreToken>()
                .Property(t => t.ReferenceId)
                .UseCollation(IdentityDatabaseSchema.BinaryIdentifierCollation);

            builder.Entity<Entities.OidcUserSession>()
                .Property(x => x.SessionId)
                .UseCollation(IdentityDatabaseSchema.BinaryIdentifierCollation);

            builder.Entity<Entities.CibaPendingState>()
                .Property(x => x.AuthReqId)
                .UseCollation(IdentityDatabaseSchema.BinaryIdentifierCollation);
            builder.Entity<Entities.CibaPendingState>()
                .Property(x => x.ConsumptionId)
                .UseCollation(IdentityDatabaseSchema.BinaryIdentifierCollation);

            builder.Entity<Entities.SsfStream>()
                .Property(x => x.StreamId)
                .UseCollation(IdentityDatabaseSchema.BinaryIdentifierCollation);
            builder.Entity<Entities.SsfStream>()
                .Property(x => x.VerificationChallengeHash)
                .UseCollation(IdentityDatabaseSchema.BinaryIdentifierCollation);

            builder.Entity<Entities.SsfSetDelivery>()
                .Property(x => x.StreamId)
                .UseCollation(IdentityDatabaseSchema.BinaryIdentifierCollation);
            builder.Entity<Entities.SsfSetDelivery>()
                .Property(x => x.DeliveryKey)
                .UseCollation(IdentityDatabaseSchema.BinaryIdentifierCollation);

            builder.Entity<Entities.DpopReplayEntry>()
                .Property(x => x.Key)
                .UseCollation(IdentityDatabaseSchema.BinaryIdentifierCollation);

            // Opaque, case-sensitive lookup key — same rule as every other
            // protocol identifier.
            builder.Entity<Entities.ProtocolStateEntry>()
                .Property(x => x.Key)
                .UseCollation(IdentityDatabaseSchema.BinaryIdentifierCollation);

            builder.Entity<Entities.ManagementClientDraftRecord>()
                .Property(x => x.Id)
                .UseCollation(IdentityDatabaseSchema.AsciiBinaryCollation);

            builder.Entity<Entities.OAuthClientCredential>()
                .Property(x => x.ClientId)
                .UseCollation(IdentityDatabaseSchema.BinaryIdentifierCollation);
        }
}
