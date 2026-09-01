using Microsoft.Extensions.DependencyInjection;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Nenhum teste pode depender do relógio da máquina para decidir se o código
/// está certo.
/// </summary>
/// <remarks>
/// Quatro testes caíram em rodadas diferentes de 2026-08-31, cada um passando
/// quando executado sozinho, e a vítima mudava a cada rodada. Só reproduziam
/// com a CPU saturada — por isso "não reproduziu na rodada seguinte" não
/// provava nada. Apareceram em três formas:
/// <list type="number">
/// <item>dormir um tempo fixo esperando trabalho de fundo terminar;</item>
/// <item>sondar um efeito até um relógio de parede estourar;</item>
/// <item>cronometrar uma operação e exigir que tenha levado menos de X.</item>
/// </list>
/// Nas três, a falha acusava a funcionalidade — "a retenção não removeu", "a
/// auditoria não gravou", "o coletor bloqueou a autenticação" — quando o que
/// faltou foi tempo de CPU. Um teste assim ensina a reexecutar até passar, e
/// esse hábito corrói a suíte inteira, porque a próxima falha real também vai
/// parecer flake.
/// <para>
/// Dormir esperando um PRAZO EXPIRAR é diferente e continua permitido: ali
/// dormir demais é inofensivo, nunca de menos. O que estas guardas proíbem é
/// dormir esperando alguém terminar, e medir para concluir.
/// </para>
/// </remarks>
public sealed class TestSynchronizationContractTests
{
    /// <summary>
    /// Esperas por tempo que sobreviveram à revisão, com a razão de cada uma.
    /// A contagem é exata de propósito: acrescentar uma espera nova a um
    /// arquivo já listado também quebra, e obriga a justificar.
    /// </summary>
    private static readonly Dictionary<string, (int Count, string Reason)> Justified =
        new(StringComparer.Ordinal)
        {
            ["ManagementUiRoutingTests.cs"] =
                (1, "Task.Delay(Timeout.InfiniteTimeSpan) — bloqueio até "
                    + "cancelamento, não espera por conclusão."),
            ["ServerSideSessionsTests.cs"] =
                (1, "Task.Delay(Timeout.InfiniteTimeSpan) — bloqueio até "
                    + "cancelamento, não espera por conclusão."),
            ["DistributedStoreTests.cs"] =
                (1, "Aguarda um TTL de 1ms expirar; dormir demais não "
                    + "invalida o teste."),
            ["DatabaseRuntimeTelemetryTests.cs"] =
                (1, "Aguarda a janela de poda de 10ms passar; dormir demais "
                    + "não invalida o teste."),
            ["ManagementUiArchitectureTests.ManagementUi.cs"] =
                (1, "Não é uma espera: é uma asserção sobre o texto-fonte de "
                    + "um componente, que verifica o debounce escrito nele."),
        };

    [Fact]
    public void No_test_synchronizes_with_background_work_by_sleeping()
    {
        var offenders = new List<string>();

        foreach (var file in EnumerateTestSources())
        {
            var name = Path.GetFileName(file);
            var found = Regex.Matches(
                File.ReadAllText(file),
                @"Task\.Delay\s*\(").Count;

            var allowed = Justified.TryGetValue(name, out var entry)
                ? entry.Count
                : 0;

            if (found != allowed)
            {
                offenders.Add(
                    $"{name}: {found} espera(s) por tempo, {allowed} "
                    + "justificada(s). Espere um sinal do trabalho (um evento, "
                    + "um contador, ou chame a operação diretamente) em vez de "
                    + "dormir; se a espera for por um prazo expirar, registre-a "
                    + "em Justified com a razão.");
            }
        }

        Assert.True(offenders.Count == 0, string.Join("\n", offenders));
    }

    /// <summary>
    /// A forma que mais enganou: sondar a tabela até um relógio de parede
    /// estourar. Falha reportando o efeito ausente, nunca o tempo que faltou.
    /// </summary>
    [Fact]
    public void No_test_polls_against_a_wall_clock_deadline()
    {
        var offenders = EnumerateTestSources()
            .Where(file => Regex.IsMatch(
                File.ReadAllText(file),
                @"while\s*\(\s*Date(Time|TimeOffset)\.UtcNow\s*<"))
            .Select(Path.GetFileName)
            .ToArray();

        Assert.True(
            offenders.Length == 0,
            "Sondagem contra relógio de parede em: "
                + string.Join(", ", offenders));
    }

    /// <summary>
    /// A terceira forma, e a que escapou das duas guardas acima: cronometrar
    /// uma operação e exigir que tenha levado menos de X.
    /// </summary>
    /// <remarks>
    /// <c>IdentityUsageMetricChannelTests</c> media uma escrita e exigia menos
    /// de 50ms para provar que o caminho de autenticação não bloqueia. Sob CPU
    /// saturada a thread é despreempada por mais que isso sem o código ter
    /// esperado nada — e o teste passava a acusar o coletor de bloquear a
    /// emissão de token. "Não bloqueia" é uma propriedade da escrita escolhida;
    /// verifique a escrita, não o cronômetro.
    /// </remarks>
    [Fact]
    public void No_test_asserts_on_measured_elapsed_time()
    {
        var offenders = EnumerateTestSources()
            .Where(file => Regex.IsMatch(
                File.ReadAllText(file),
                @"Stopwatch\.StartNew|new\s+Stopwatch"))
            .Select(Path.GetFileName)
            .ToArray();

        Assert.True(
            offenders.Length == 0,
            "Cronometragem em teste (o relógio da máquina não é o "
                + "comportamento sob teste): " + string.Join(", ", offenders));
    }

    /// <summary>
    /// O host de gestão precisa ter o schema antes dos serviços de fundo.
    /// </summary>
    /// <remarks>
    /// Os <c>IHostedService</c> arrancam antes de <c>InitializeAsync</c>, onde
    /// ficava o <c>EnsureCreatedAsync</c>. Sem o bootstrap, toda execução
    /// registrava <c>no such table: managementauditevents</c> e
    /// <c>no such table: dataprotectionkeys</c> — o primeiro virava um aviso
    /// engolido pela retenção, o segundo impedia o anel de chaves de persistir
    /// justamente nos testes que protegem e depois desprotegem um rascunho.
    /// <para>
    /// Este teste não chama <c>InitializeAsync</c> de propósito: é exatamente
    /// o instante em que os serviços de fundo já estão rodando e a semeadura
    /// ainda não aconteceu.
    /// </para>
    /// </remarks>
    [Fact]
    public void Management_host_schema_exists_before_seeding()
    {
        using var factory = new Infrastructure.ManagementTestFactory();

        using var scope = factory.Services.CreateScope();
        var database = scope.ServiceProvider
            .GetRequiredService<Sufficit.Identity.Core.Data.AppDbContext>();

        // Consultar uma tabela ausente lança; sobreviver à consulta É a
        // asserção. Não afirmo contagem: o anel de chaves já grava a primeira
        // chave no arranque, e fixar esse número aqui seria trocar uma
        // fragilidade por outra.
        Assert.Null(Record.Exception(
            () => database.ManagementAuditEvents.Count()));
        Assert.Null(Record.Exception(
            () => database.DataProtectionKeys.Count()));
    }

    private static IEnumerable<string> EnumerateTestSources() =>
        Directory
            .EnumerateFiles(TestSourceDirectory(), "*.cs", SearchOption.AllDirectories)
            // Este arquivo cita as formas proibidas para explicá-las.
            .Where(file => Path.GetFileName(file) != OwnFileName())
            .Where(file => !file.Contains(
                    $"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}",
                    StringComparison.Ordinal)
                && !file.Contains(
                    $"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}",
                    StringComparison.Ordinal));

    private static string OwnFileName([CallerFilePath] string sourceFile = "") =>
        Path.GetFileName(sourceFile);

    private static string TestSourceDirectory([CallerFilePath] string sourceFile = "") =>
        Path.GetDirectoryName(sourceFile)
            ?? throw new InvalidOperationException(
                "Unable to resolve the test source directory.");
}
