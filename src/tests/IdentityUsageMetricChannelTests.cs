using System.Runtime.CompilerServices;
using Sufficit.Identity.Core.Metrics;
using Sufficit.Identity.STS.Metrics;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class IdentityUsageMetricChannelTests
{
    [Fact]
    public void Full_collector_drops_without_blocking_authentication()
    {
        var runtime = new IdentityMetricsRuntimeState();
        var channel = new IdentityUsageMetricChannel(runtime);
        var metric = new IdentityUsageMetric(
            DateTime.UtcNow, "client", "token_issued", "token",
            "client_credentials", "succeeded", null);

        for (var index = 0; index < IdentityUsageMetricChannel.Capacity; index++)
            Assert.True(channel.TryRecord(metric));

        // Nada drena este canal, então uma escrita que esperasse por espaço
        // esperaria para sempre: chegar até a linha seguinte com um "false" na
        // mão já é a prova de que a chamada recusou em vez de aguardar.
        //
        // A versão anterior media isto com Stopwatch e exigia menos de 50ms.
        // Sob CPU saturada a thread é despreempada por mais que isso sem o
        // código ter esperado nada, e o teste então acusava o caminho de
        // autenticação de bloquear — culpando a funcionalidade pelo relógio.
        Assert.False(channel.TryRecord(metric));

        Assert.Equal(IdentityUsageMetricChannel.Capacity, runtime.Accepted);
        Assert.Equal(1, runtime.Dropped);
        Assert.Equal(IdentityUsageMetricChannel.Capacity, runtime.QueueDepth);
    }

    /// <summary>
    /// A recusa imediata é uma propriedade da escrita escolhida, não do tempo
    /// que ela levou numa medição.
    /// </summary>
    /// <remarks>
    /// O teste acima só pegaria uma espera INFINITA (por travamento). Uma
    /// espera limitada — trocar <c>TryWrite</c> por um <c>WriteAsync</c> com
    /// prazo, por exemplo — continuaria devolvendo <c>false</c> e passaria,
    /// enquanto atrasaria toda emissão de token sob carga. É essa troca que
    /// esta asserção vigia.
    /// </remarks>
    [Fact]
    public void Recording_uses_a_non_waiting_write()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot(), "src", "sts", "Metrics",
            "IdentityUsageMetricChannel.cs"));

        Assert.Contains("Channel.Writer.TryWrite(", source, StringComparison.Ordinal);
        Assert.DoesNotContain("WriteAsync", source, StringComparison.Ordinal);
        Assert.DoesNotContain("WaitToWriteAsync", source, StringComparison.Ordinal);
        Assert.DoesNotContain(".Wait()", source, StringComparison.Ordinal);
        Assert.DoesNotContain(".GetAwaiter().GetResult()", source, StringComparison.Ordinal);
    }

    private static string RepositoryRoot([CallerFilePath] string sourceFile = "") =>
        Path.GetFullPath(Path.Combine(
            Path.GetDirectoryName(sourceFile)
                ?? throw new InvalidOperationException(
                    "Unable to resolve the test source directory."),
            "..",
            ".."));
}
