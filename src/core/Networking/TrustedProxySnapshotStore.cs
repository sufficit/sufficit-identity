using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Core.Networking;

/// <summary>Serializes refresh and local commits; readers only capture immutable memory.</summary>
public sealed class TrustedProxySnapshotStore
{
    private readonly IServiceScopeFactory scopes;
    private readonly ILogger<TrustedProxySnapshotStore> logger;
    private readonly ITrustedProxyChangePublisher? publisher;
    private readonly TimeProvider clock;
    private readonly SemaphoreSlim refreshGate = new(1, 1);
    private TrustedProxySnapshot current;

    /// <summary>
    /// The file-configured proxies alone. A stable instance, so forwarding can
    /// cache its middleware for it exactly as it does for a database snapshot.
    /// </summary>
    private readonly TrustedProxySnapshot fileBaseline;
    private TrustedProxySyncDiagnostics diagnostics = new();
    public TrustedProxySnapshot Current => Volatile.Read(ref current);
    public TrustedProxySyncDiagnostics Diagnostics => Volatile.Read(ref diagnostics);
    public TrustedProxySynchronizationOptions Synchronization { get; }
    public bool NotificationsEnabled => publisher?.Enabled == true;
    public bool NotificationsConnected => publisher?.Connected == true;
    public bool IsFresh => Diagnostics.LastConfirmedAtUtc is { } confirmed
        && clock.GetUtcNow() - confirmed <= TimeSpan.FromSeconds(Synchronization.MaxStaleSeconds);

    public TrustedProxySnapshotState State => ResolveForwarding().State;

    /// <summary>
    /// Decides which proxy list forwarding applies. Freshness and validity are
    /// separate questions: a stale database list is not trusted, but that does
    /// not have to mean refusing every request — the file-configured proxies
    /// are the deployment's own baseline and remain valid without the database.
    /// </summary>
    public TrustedProxyForwarding ResolveForwarding()
    {
        if (IsFresh)
            return new(TrustedProxySnapshotState.Fresh, Current);
        return Synchronization.StaleSnapshotMode == TrustedProxyStaleSnapshotMode.Reject
            ? new(TrustedProxySnapshotState.StaleRejected, null)
            : new(TrustedProxySnapshotState.StaleFileBaseline, fileBaseline);
    }

    public TrustedProxySnapshotStore(IServiceScopeFactory scopes,
        IOptions<TrustedProxyOptions> options, ILogger<TrustedProxySnapshotStore> logger,
        ITrustedProxyChangePublisher? publisher = null, TimeProvider? clock = null)
    {
        this.scopes = scopes;
        this.logger = logger;
        this.publisher = publisher;
        this.clock = clock ?? TimeProvider.System;
        Synchronization = options.Value.ProxySynchronization;
        Synchronization.Validate();
        var baseline = TrustedProxyValidation.Normalize(options.Value.TrustedProxies);
        TrustedProxyValidation.ValidateForwardLimit(options.Value.ForwardLimit);
        current = new(baseline, [], baseline, options.Value.ForwardLimit, null, "initial", null);
        fileBaseline = new(baseline, [], baseline, options.Value.ForwardLimit, null, "file-baseline", null);
    }

    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        await refreshGate.WaitAsync(cancellationToken);
        try
        {
            await using var scope = scopes.CreateAsyncScope();
            var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            if (Current.UpdatedAtUtc is not null)
            {
                diagnostics = diagnostics with { RevisionReads = diagnostics.RevisionReads + 1 };
                var revision = await database.TrustedProxyConfigurations.AsNoTracking()
                    .Where(x => x.Id == 1).Select(x => x.Revision).SingleAsync(cancellationToken);
                if (revision == Current.Revision)
                {
                    Volatile.Write(ref diagnostics, diagnostics with
                    { LastConfirmedAtUtc = clock.GetUtcNow(), ConsecutiveFailures = 0 });
                    return;
                }
            }
            diagnostics = diagnostics with { ContentReads = diagnostics.ContentReads + 1 };
            // Use the revision returned WITH the content, not the earlier scalar read.
            var entity = await database.TrustedProxyConfigurations.AsNoTracking()
                .SingleAsync(x => x.Id == 1, cancellationToken);
            Apply(entity);
        }
        catch
        {
            Volatile.Write(ref diagnostics, diagnostics with { ConsecutiveFailures = diagnostics.ConsecutiveFailures + 1 });
            throw;
        }
        finally { refreshGate.Release(); }
    }

    /// <summary>The commit and memory swap share the refresh gate. No post-save SELECT.</summary>
    public async Task CommitAsync(Func<CancellationToken, Task<TrustedProxyConfiguration>> persist,
        CancellationToken cancellationToken = default)
    {
        string revision;
        await refreshGate.WaitAsync(cancellationToken);
        try
        {
            var entity = await persist(cancellationToken);
            // Once committed, client cancellation must not prevent the local memory update.
            Apply(entity);
            revision = entity.Revision;
        }
        finally { refreshGate.Release(); }

        var notified = false;
        if (publisher?.Enabled == true)
        {
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                notified = await publisher.PublishAsync(revision, timeout.Token);
            }
            catch (Exception exception)
            {
                logger.LogWarning("Trusted proxy configuration committed; notification failed ({ErrorType}).",
                    exception.GetType().Name);
            }
        }
        await refreshGate.WaitAsync(CancellationToken.None);
        try
        {
            if (Current.Revision == revision)
                Volatile.Write(ref diagnostics, diagnostics with { NotificationPending = publisher?.Enabled == true && !notified });
        }
        finally { refreshGate.Release(); }
    }

    private void Apply(TrustedProxyConfiguration entity)
    {
        var networks = TrustedProxyValidation.Normalize(JsonSerializer.Deserialize<string[]>(entity.NetworksJson)
            ?? throw new InvalidOperationException("Invalid stored trusted proxy configuration."));
        TrustedProxyValidation.ValidateForwardLimit(entity.ForwardLimit);
        var previous = Current;
        var effective = previous.FileNetworks.Concat(networks).Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal).ToImmutableArray();
        Volatile.Write(ref current, new(previous.FileNetworks, networks, effective,
            previous.FileForwardLimit, entity.ForwardLimit, entity.Revision, entity.UpdatedAtUtc));
        var now = clock.GetUtcNow();
        Volatile.Write(ref diagnostics, diagnostics with { LastConfirmedAtUtc = now, LastChangedAtUtc = now,
            Generation = diagnostics.Generation + 1, ConsecutiveFailures = 0, NotificationPending = false });
        logger.LogInformation("Trusted proxy snapshot loaded: revision {Revision}, {NetworkCount} networks, {ForwardLimit} hops.",
            entity.Revision, effective.Length, Current.ForwardLimit);
    }
}
