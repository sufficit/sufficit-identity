using Sufficit.Identity.Core.Networking;

namespace Sufficit.Identity.Server;

internal sealed class TrustedProxyRefreshWorker(TrustedProxySnapshotStore snapshots,
    TrustedProxyRefreshSignal signal, ILogger<TrustedProxyRefreshWorker> logger) : BackgroundService
{
    private static readonly int[] RetrySeconds = [1, 2, 4, 8, 15, 30];

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var next = DateTimeOffset.UtcNow;
        string? expected = null;
        var attempt = 0;
        var recovering = false;
        while (!stoppingToken.IsCancellationRequested)
        {
            var delay = next - DateTimeOffset.UtcNow;
            if (delay > TimeSpan.Zero)
            {
                using var wait = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                wait.CancelAfter(delay);
                try
                {
                    expected = await signal.Reader.ReadAsync(wait.Token);
                    // Coalesce the whole burst before starting SQL; later arrivals remain queued.
                    while (signal.Reader.TryRead(out var newer)) expected = newer;
                    recovering = true;
                    attempt = 0;
                    await Task.Delay(100, stoppingToken);
                }
                catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested) { }
            }
            if (stoppingToken.IsCancellationRequested) break;
            var success = await RefreshOnceAsync(stoppingToken);
            // GUID revisions are hints, never an ordering. An obsolete hint cannot pin a node forever.
            var unresolved = recovering && !string.IsNullOrEmpty(expected) && (!success || snapshots.Current.Revision != expected);
            if ((unresolved || !success) && attempt < RetrySeconds.Length)
                next = DateTimeOffset.UtcNow.AddSeconds(RetrySeconds[attempt++] * (0.9 + Random.Shared.NextDouble() * 0.2));
            else
            {
                if (unresolved)
                    logger.LogWarning("Trusted proxy invalidation recovery window ended; periodic reconciliation will continue (revision hints are unordered).");
                expected = null;
                recovering = false;
                attempt = 0;
                next = DateTimeOffset.UtcNow.AddSeconds(snapshots.Synchronization.ReconcileSeconds
                    * (0.9 + Random.Shared.NextDouble() * 0.2));
            }
        }
    }

    internal async Task<bool> RefreshOnceAsync(CancellationToken stoppingToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(snapshots.Synchronization.RefreshTimeoutSeconds));
        try
        {
            await snapshots.RefreshAsync(timeout.Token);
            logger.LogDebug("Trusted proxy reconciliation completed: revision {Revision}, scalar reads {RevisionReads}.",
                snapshots.Current.Revision, snapshots.Diagnostics.RevisionReads);
            return true;
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return false; }
        catch (Exception exception)
        {
            logger.LogError("Trusted proxy refresh failed ({ErrorType}); retaining the last valid snapshot within its freshness limit.",
                exception.GetType().Name);
            return false;
        }
    }
}
