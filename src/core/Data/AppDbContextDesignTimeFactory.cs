using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Core.Data;

/// <summary>
/// Design-time factory para <see cref="AppDbContext"/> — usado apenas pelo
/// <c>dotnet ef migrations add</c> (e comandos relacionados). Sem isto, o EF
/// tooling tenta resolver <c>DbContextOptions&lt;AppDbContext&gt;</c> via DI
/// rodando <c>Program.cs</c> do startup project, mas o STS exige connection
/// string válida + ambiente Development para subir — inadequado para
/// design-time. Esta factory fornece um <c>DbContextOptions</c> mínimo, com uma
/// conexão fictícia que nunca é aberta, só para o EF ler o modelo e gerar a
/// migration.
///
/// O provider Oracle é provisório para o modelo EF 10. O banco continua sendo
/// MariaDB e toda migration gerada deve ser exercitada contra a versão exata
/// desse engine antes de qualquer publicação.
/// </summary>
public sealed class AppDbContextDesignTimeFactory
    : IDesignTimeDbContextFactory<AppDbContext>
{
    public AppDbContext CreateDbContext(string[] args)
    {
        // Provisional Oracle compatibility provider used by the EF 10 model.
        // The real database remains MariaDB; every generated migration is
        // validated against the configured MariaDB compatibility baseline.
        // This dummy connection is never opened at design time.
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseMySQL(
                "server=localhost;database=identity_design;user=root",
                mysql => mysql.MigrationsHistoryTable(IdentityDatabaseSchema.MigrationsHistoryTable))
            .Options;

        return new AppDbContext(options);
    }
}
