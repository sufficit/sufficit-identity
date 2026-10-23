using System.Collections.Immutable;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenIddict.EntityFrameworkCore.Models;
using StackExchange.Redis;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Services;

namespace Sufficit.Identity.STS.Security;

/// <summary>
/// Disabled clients in memory (plan E1). Loaded before the host serves, re-read
/// every 30 seconds (one small query: only rows carrying the marker), and at
/// once when a replica announces a change on the shared Redis. A failed read
/// keeps the last known set: it never re-enables a client by accident.
/// </summary>
internal sealed class DisabledClientRegistry(
    IDbContextFactory<AppDbContext> databaseFactory,
    ILogger<DisabledClientRegistry> logger,
    IConnectionMultiplexer? redis = null) : BackgroundService, IDisabledClientRegistry
{
    internal static readonly RedisChannel Channel = RedisChannel.Literal("sufficit:identity:client-state");
    internal static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);

    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private ImmutableHashSet<string> _disabled = ImmutableHashSet<string>.Empty.WithComparer(StringComparer.Ordinal);

    public bool IsDisabled(string? clientId) =>
        !string.IsNullOrEmpty(clientId) && Volatile.Read(ref _disabled).Contains(clientId);

    public async Task PublishChangeAsync(CancellationToken cancellationToken = default)
    {
        await RefreshAsync(cancellationToken);
        if (redis is null) return;
        try
        {
            await redis.GetSubscriber().PublishAsync(Channel, "changed");
        }
        catch (Exception exception) when (exception is RedisException or TimeoutException)
        {
            logger.LogWarning(exception, "Client state change not announced; other replicas pick it up within {Interval}.", Interval);
        }
    }

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        await RefreshAsync(cancellationToken);
        if (redis is not null)
        {
            try
            {
                await redis.GetSubscriber().SubscribeAsync(Channel, (_, _) => _ = RefreshAsync(CancellationToken.None));
            }
            catch (Exception exception) when (exception is RedisException or TimeoutException)
            {
                logger.LogWarning(exception, "Client state announcements unavailable; relying on the {Interval} re-read.", Interval);
            }
        }
        await base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
                await RefreshAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    internal async Task RefreshAsync(CancellationToken cancellationToken)
    {
        await _refreshGate.WaitAsync(cancellationToken);
        try
        {
            await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
            var rows = await database.Set<OpenIddictEntityFrameworkCoreApplication>()
                .AsNoTracking()
                .Where(application => application.Properties != null
                    && application.Properties.Contains(ClientOperationalState.PropertyName))
                .Select(application => new { application.ClientId, application.Properties })
                .ToListAsync(cancellationToken);
            var current = rows
                .Where(row => row.ClientId is not null && ClientOperationalState.Read(row.Properties) is not null)
                .Select(row => row.ClientId!)
                .ToImmutableHashSet(StringComparer.Ordinal);
            var previous = Interlocked.Exchange(ref _disabled, current);
            if (!previous.SetEquals(current))
                logger.LogInformation("Disabled clients: {Count} ({Clients}).", current.Count, string.Join(", ", current.Order(StringComparer.Ordinal)));
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning(exception, "Disabled clients could not be re-read; keeping the last known set.");
        }
        finally
        {
            _refreshGate.Release();
        }
    }
}
