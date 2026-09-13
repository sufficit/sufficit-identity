using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Core.Data;

/// <summary>
/// Design-time factory for <see cref="AppDbContext"/> — used only by
/// <c>dotnet ef migrations add</c> (and related commands). Without this, the EF
/// tooling tries to resolve <c>DbContextOptions&lt;AppDbContext&gt;</c> via DI by
/// running the startup project's <c>Program.cs</c>, but the STS requires a valid
/// connection string + Development environment to start up — unsuitable for
/// design-time. This factory provides a minimal <c>DbContextOptions</c>, with a
/// dummy connection that is never opened, just so EF can read the model and
/// generate the migration.
///
/// The Oracle provider is provisional for the EF 10 model. The database remains
/// MariaDB, and every generated migration must be exercised against the exact
/// version of that engine before any publication.
/// </summary>
public sealed class AppDbContextDesignTimeFactory
    : IDesignTimeDbContextFactory<AppDbContext>
{
    public AppDbContext CreateDbContext(string[] args)
    {
        // Pomelo provider (Sufficit fork, EF Core 10). The real database remains
        // MariaDB; every generated migration is validated against the configured
        // MariaDB compatibility baseline. This dummy connection is never opened
        // at design time; a fixed MariaDbServerVersion avoids AutoDetect round-trip.
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseMySql(
                "server=localhost;database=identity_design;user=root",
                new MariaDbServerVersion(new Version(10, 4, 34)),
                mysql => mysql.MigrationsHistoryTable(IdentityDatabaseSchema.MigrationsHistoryTable))
            .Options;

        return new AppDbContext(options);
    }
}
