using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Core.Data;

internal static class TrustedProxyMapping
{
    internal static void Apply(ModelBuilder builder)
    {
        builder.Entity<TrustedProxyConfiguration>(b =>
        {
            b.ToTable("trustedproxyconfiguration");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedNever();
            b.Property(x => x.NetworksJson).HasColumnName("networksjson").HasColumnType("longtext").IsRequired();
            b.Property(x => x.ForwardLimit).HasColumnName("forwardlimit");
            b.Property(x => x.Revision).HasColumnName("revision").HasMaxLength(36).IsConcurrencyToken();
            b.Property(x => x.UpdatedAtUtc).HasColumnName("updatedatutc").HasColumnType("datetime(6)");
            b.HasData(new TrustedProxyConfiguration());
        });
    }
}
