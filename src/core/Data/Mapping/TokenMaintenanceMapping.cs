using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Core.Data;

internal static class TokenMaintenanceMapping
{
    internal static void Apply(ModelBuilder builder)
    {
        builder.Entity<TokenMaintenance>(b =>
        {
            b.ToTable("tokenmaintenance");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedNever();
            b.Property(x => x.Revision).HasMaxLength(36).IsConcurrencyToken();
            b.Property(x => x.Owner).HasMaxLength(128);
            b.Property(x => x.CurrentRunId).HasMaxLength(36);
            b.HasData(new TokenMaintenance());
        });
        builder.Entity<TokenMaintenanceRun>(b =>
        {
            b.ToTable("tokenmaintenanceruns");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasMaxLength(36);
            b.Property(x => x.Owner).HasMaxLength(128);
            b.Property(x => x.Status).HasMaxLength(24);
            b.HasIndex(x => x.StartedAtUtc);
        });
        foreach (var type in new[] { typeof(TokenMaintenance), typeof(TokenMaintenanceRun) })
            foreach (var property in builder.Entity(type).Metadata.GetProperties())
            {
                property.SetColumnName(property.Name.ToLowerInvariant());
                if (property.ClrType == typeof(DateTime) || property.ClrType == typeof(DateTime?))
                    property.SetColumnType("datetime(6)");
            }
    }
}
