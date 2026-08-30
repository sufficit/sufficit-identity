using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Entities;


namespace Sufficit.Identity.Core.Data;

internal static class MappingHelpers
{
        /// <summary>
        /// Applies <c>HasColumnName</c> for each (property, column) pair.
        /// </summary>
        internal static void SnakeCaseColumns<T>(EntityTypeBuilder<T> b,
            params (string Property, string Column)[] mappings)
            where T : class
        {
            foreach (var (prop, col) in mappings)
            {
                b.Property(prop).HasColumnName(col);
            }
        }
}
