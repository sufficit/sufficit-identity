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
internal static class DataProtectionMapping
{
        /// <summary>
        /// Maps the single ASP.NET Core Data Protection key-ring entity
        /// (<c>DataProtectionKey</c>), persisted here via
        /// <c>PersistKeysToDbContext&lt;AppDbContext&gt;()</c> (P0 #B4). Table
        /// name follows the same lowercase-no-separators convention as the
        /// Identity tables above (default PascalCase columns: Id, FriendlyName,
        /// Xml — NOT the snake_case convention used for the OpenIddict tables).
        ///
        /// PRODUCTION SQL RUNBOOK: dev/tests create this table automatically via
        /// <c>Database.EnsureCreatedAsync()</c>; production provisions schema
        /// from manual SQL (docs/migration/sql/*), which MUST add this table
        /// (columns: Id INT PK IDENTITY, FriendlyName TEXT NULL, Xml TEXT/
        /// LONGTEXT NULL) BEFORE deploying this change — reading/writing the
        /// key ring against a schema that predates this table throws (the
        /// query fails with "table doesn't exist"), it does not silently fall
        /// back to an unpersisted key ring.
        /// </summary>
        internal static void Apply(ModelBuilder builder)
        {
            builder.Entity<DataProtectionKey>(b =>
            {
                b.ToTable("dataprotectionkeys");
                MappingHelpers.SnakeCaseColumns(b, [
                    ("Id", "id"),
                    ("FriendlyName", "friendlyname"),
                    ("Xml", "xml"),
                ]);
            });
        }
}
