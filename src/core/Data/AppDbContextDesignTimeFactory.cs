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
/// design-time. Esta factory fornece um DbContextOptions mínimo (SQLite
/// in-memory) só para o EF conseguir ler o modelo e gerar a migration.
///
/// A migration gerada é provider-agnóstica o suficiente para MySQL/Oracle
/// (usa tipos genéricos do EF Core; anotações específicas como
/// <c>timestamp</c> + <c>UTC_TIMESTAMP()</c> estão no <c>OnModelCreating</c>
/// e viram annotations na migration).
/// </summary>
public sealed class AppDbContextDesignTimeFactory
    : IDesignTimeDbContextFactory<AppDbContext>
{
    public AppDbContext CreateDbContext(string[] args)
    {
        // Provider Oracle MySql.EntityFrameworkCore — mesmo provider de produção
        // (Stage 1 da migração Pomelo→Oracle). Connection string dummy: o EF
        // tooling não abre conexão para gerar migrations, só precisa saber o
        // provider para emitir annotations corretas (MySQL-specific types,
        // identity columns, etc).
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseMySQL("server=localhost;database=identity_design;user=root;password=dummy")
            .Options;

        return new AppDbContext(options);
    }
}
