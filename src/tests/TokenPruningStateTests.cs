using Sufficit.Identity.Server;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class TokenPruningStateTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "identity-pruning-" + Guid.NewGuid().ToString("N"));
    private string StatePath => Path.Combine(directory, "success.json");

    [Fact]
    public async Task Zero_deletions_are_a_success_and_the_state_survives_failures()
    {
        var success = await TokenPruningState.RunAsync(StatePath, _ => Task.FromResult((0L, 0L)), default);
        Assert.Equal(success, await TokenPruningState.ReadFreshAsync(StatePath, DateTimeOffset.UtcNow, TimeSpan.FromHours(14)));
        var original = await File.ReadAllTextAsync(StatePath);
        await Assert.ThrowsAsync<InvalidOperationException>(() => TokenPruningState.RunAsync(StatePath,
            _ => throw new InvalidOperationException("Authorization pruning failed after deleting tokens"), default));
        Assert.Equal(original, await File.ReadAllTextAsync(StatePath));
        using var cancelled = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => TokenPruningState.RunAsync(StatePath,
            _ => { cancelled.Cancel(); return Task.FromResult((2L, 3L)); }, cancelled.Token));
        Assert.Equal(original, await File.ReadAllTextAsync(StatePath));
    }

    [Fact]
    public async Task Missing_corrupt_stale_and_future_success_are_not_healthy()
    {
        await Assert.ThrowsAnyAsync<IOException>(() => TokenPruningState.ReadFreshAsync(StatePath, DateTimeOffset.UtcNow, TimeSpan.FromHours(14)));
        var success = await TokenPruningState.RunAsync(StatePath, _ => Task.FromResult((1L, 2L)), default);
        await Assert.ThrowsAsync<InvalidDataException>(() => TokenPruningState.ReadFreshAsync(StatePath, success.LastSuccessUtc.AddHours(15), TimeSpan.FromHours(14)));
        await Assert.ThrowsAsync<InvalidDataException>(() => TokenPruningState.ReadFreshAsync(StatePath, success.LastSuccessUtc.AddMinutes(-6), TimeSpan.FromHours(14)));
        await File.WriteAllTextAsync(StatePath, "malformed");
        await Assert.ThrowsAsync<System.Text.Json.JsonException>(() => TokenPruningState.ReadFreshAsync(StatePath, DateTimeOffset.UtcNow, TimeSpan.FromHours(14)));
    }

    [Fact]
    public async Task Concurrent_sweep_cannot_enter_while_the_first_holds_the_lease()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var first = TokenPruningState.RunAsync(StatePath, async _ => { entered.SetResult(); await release.Task; return (1L, 0L); }, default);
        await entered.Task;
        try
        {
            await Assert.ThrowsAsync<IOException>(() => TokenPruningState.RunAsync(StatePath,
                _ => throw new Exception("Must not execute"), default));
        }
        finally { release.SetResult(); await first; }
    }

    public void Dispose() { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }
}
