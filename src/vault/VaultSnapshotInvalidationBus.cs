using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace Sufficit.Identity.Vault;

/// <summary>
/// Optional cross-replica invalidation channel for Vault snapshots. Redis is
/// an optimization here: if it is unavailable, the snapshot's bounded TTL
/// and background refresh remain the safety boundary.
/// </summary>
internal interface IVaultSnapshotInvalidationBus
{
    Task PublishAsync(
        VaultSnapshotInvalidation invalidation,
        CancellationToken cancellationToken);

    Task SubscribeAsync(
        Func<VaultSnapshotInvalidation, Task> handler,
        CancellationToken cancellationToken);

    Task UnsubscribeAsync(CancellationToken cancellationToken);
}

internal sealed record VaultSnapshotInvalidation(
    string Kind,
    string CacheKey,
    string? ScopeHash);

internal sealed class RedisVaultSnapshotInvalidationBus(
    IConnectionMultiplexer connection,
    ILogger<RedisVaultSnapshotInvalidationBus> logger) : IVaultSnapshotInvalidationBus
{
    internal const string ChannelName = "sufficit:identity:vault:snapshot:invalidate:v1";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly ISubscriber _subscriber = connection.GetSubscriber();
    private Action<RedisChannel, RedisValue>? _subscription;

    public async Task PublishAsync(
        VaultSnapshotInvalidation invalidation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            await _subscriber.PublishAsync(
                RedisChannel.Literal(ChannelName),
                JsonSerializer.Serialize(invalidation, JsonOptions));
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // Pub/Sub is deliberately best effort. The local cache was
            // already invalidated and every entry has a hard TTL fallback.
            logger.LogWarning(
                exception,
                "Vault snapshot invalidation publish failed; replicas will converge through TTL.");
        }
    }

    public async Task SubscribeAsync(
        Func<VaultSnapshotInvalidation, Task> handler,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(handler);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            _subscription = (_, value) =>
            {
                var ignored = DispatchAsync(value, handler);
            };
            await _subscriber.SubscribeAsync(RedisChannel.Literal(ChannelName), _subscription);
            logger.LogInformation("Vault snapshot Redis invalidation subscription is active.");
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            _subscription = null;
            logger.LogWarning(
                exception,
                "Vault snapshot Redis invalidation subscription unavailable; replicas will converge through TTL.");
        }
    }

    public async Task UnsubscribeAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var subscription = _subscription;
        _subscription = null;
        if (subscription is null) return;

        try
        {
            await _subscriber.UnsubscribeAsync(RedisChannel.Literal(ChannelName), subscription);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            logger.LogDebug(exception, "Vault snapshot Redis invalidation unsubscribe failed.");
        }
    }

    private async Task DispatchAsync(
        RedisValue value,
        Func<VaultSnapshotInvalidation, Task> handler)
    {
        try
        {
            var invalidation = JsonSerializer.Deserialize<VaultSnapshotInvalidation>(
                value.ToString(),
                JsonOptions);
            if (invalidation is not null)
            {
                await handler(invalidation);
            }
        }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Invalid Vault snapshot invalidation message received from Redis.");
        }
    }
}

internal sealed class VaultSnapshotInvalidationService(
    VaultSnapshotCache snapshots,
    IVaultSnapshotInvalidationBus bus,
    ILogger<VaultSnapshotInvalidationService> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await bus.SubscribeAsync(
            invalidation =>
            {
                snapshots.ApplyRemoteInvalidation(invalidation);
                return Task.CompletedTask;
            },
            cancellationToken);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            await bus.UnsubscribeAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            logger.LogDebug(exception, "Vault snapshot invalidation service shutdown failed.");
        }
    }
}
