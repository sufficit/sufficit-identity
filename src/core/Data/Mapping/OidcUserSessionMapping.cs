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
internal static class OidcUserSessionMapping
{
        /// <summary>
        /// Maps the server-side OIDC session table. Naming follows the Sufficit
        /// lowercase-no-prefix convention (e.g. <c>oidcusersessions</c>), matching
        /// the SSF/SCIM/branding tables rather than the snake_case-with-underscores
        /// used for the OpenIddict tables.
        /// </summary>
        internal static void Apply(ModelBuilder builder)
        {
            builder.Entity<Entities.OidcUserSession>(b =>
            {
                b.ToTable("oidcusersessions");
                b.HasKey(x => x.Id);
                b.Property(x => x.Id).ValueGeneratedOnAdd();
                b.Property(x => x.SessionId)
                    .HasMaxLength(IdentityDatabaseSchema.OidcSessionIdLength)
                    .IsRequired();
                b.Property(x => x.Subject)
                    .HasMaxLength(IdentityDatabaseSchema.OpenIddictSubjectLength)
                    .IsRequired();
                b.Property(x => x.RemoteIpAddress)
                    .HasMaxLength(IdentityDatabaseSchema.OidcSessionRemoteIpLength);
                b.Property(x => x.UserAgent)
                    .HasMaxLength(IdentityDatabaseSchema.OidcSessionUserAgentLength);
                b.Property(x => x.ProtectedTicket).HasColumnType("longblob").IsRequired();
                b.Property(x => x.CreatedAtUtc).HasColumnType("datetime(6)").IsRequired();
                b.Property(x => x.LastActivityUtc).HasColumnType("datetime(6)").IsRequired();
                b.Property(x => x.ExpiresUtc).HasColumnType("datetime(6)");

                // The sid is the ITicketStore key — one row per browser session.
                b.HasIndex(x => x.SessionId)
                    .IsUnique()
                    .HasDatabaseName("AK_oidcusersessions_sessionid");
                // Enumerate/revoke all sessions for a subject (per-device list + kill-all).
                b.HasIndex(x => x.Subject)
                    .HasDatabaseName("IX_oidcusersessions_subject");
                // Lazy expiry sweep: find expired rows cheaply.
                b.HasIndex(x => x.ExpiresUtc)
                    .HasDatabaseName("IX_oidcusersessions_expiresutc");

                MappingHelpers.SnakeCaseColumns(b, [
                    ("Id", "id"),
                    ("SessionId", "sessionid"),
                    ("Subject", "subject"),
                    ("RemoteIpAddress", "remoteipaddress"),
                    ("UserAgent", "useragent"),
                    ("CreatedAtUtc", "createdatutc"),
                    ("LastActivityUtc", "lastactivityutc"),
                    ("ExpiresUtc", "expiresutc"),
                    ("ProtectedTicket", "protectedticket"),
                ]);
            });
        }
}
