using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.STS;

/// <summary>
/// Durable, expiring key/value state for protocol features that would otherwise
/// live only in <c>IDistributedCache</c> — which defaults to process-local
/// memory and therefore silently stops being shared the moment a deployment
/// runs more than one replica (eval 2026-08-30, F-4).
/// </summary>
/// <remarks>
/// Both a synchronous and an asynchronous surface are exposed because the
/// callers genuinely differ: the DPoP nonce store is synchronous by interface,
/// while the logout dispatcher and the passkey ticket store are async. Wrapping
/// one over the other would either block a request thread or force a fake async
/// path, so each is implemented directly.
/// </remarks>
internal interface IProtocolStateStore
{
    byte[]? Get(string purpose, string key);

    void Set(string purpose, string key, byte[] payload, TimeSpan lifetime);

    void Remove(string purpose, string key);

    Task<byte[]?> GetAsync(
        string purpose,
        string key,
        CancellationToken cancellationToken = default);

    Task SetAsync(
        string purpose,
        string key,
        byte[] payload,
        TimeSpan lifetime,
        CancellationToken cancellationToken = default);

    Task RemoveAsync(
        string purpose,
        string key,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Database-backed <see cref="IProtocolStateStore"/>. Mirrors the shape already
/// used by <c>DatabaseDpopReplayCache</c> and <c>DatabaseCibaPendingRequestStore</c>:
/// a short-lived context from the factory, and an occasional sweep of expired
/// rows amortized across calls instead of a background service.
/// </summary>
internal sealed class DatabaseProtocolStateStore(
    IDbContextFactory<AppDbContext> databaseFactory,
    TimeProvider? timeProvider = null) : IProtocolStateStore
{
    // Sweep roughly once every 256 writes. Frequent enough that expired rows do
    // not accumulate, rare enough that it never dominates a request.
    private const int CleanupInterval = 256;

    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private int _cleanupCounter;

    public byte[]? Get(string purpose, string key)
    {
        var storageKey = StorageKey(purpose, key);
        using var database = databaseFactory.CreateDbContext();
        var entry = database.ProtocolStateEntries.Find(storageKey);
        return Unexpired(entry);
    }

    public async Task<byte[]?> GetAsync(
        string purpose,
        string key,
        CancellationToken cancellationToken = default)
    {
        var storageKey = StorageKey(purpose, key);
        await using var database = await databaseFactory.CreateDbContextAsync(
            cancellationToken);
        var entry = await database.ProtocolStateEntries.FindAsync(
            [storageKey],
            cancellationToken);
        return Unexpired(entry);
    }

    public void Set(string purpose, string key, byte[] payload, TimeSpan lifetime)
    {
        var storageKey = StorageKey(purpose, key);
        using var database = databaseFactory.CreateDbContext();
        var now = _timeProvider.GetUtcNow().UtcDateTime;

        var existing = database.ProtocolStateEntries.Find(storageKey);
        if (existing is null)
        {
            database.ProtocolStateEntries.Add(new ProtocolStateEntry
            {
                Key = storageKey,
                Purpose = purpose,
                Payload = payload,
                ExpiresAtUtc = now + lifetime,
            });
        }
        else
        {
            existing.Purpose = purpose;
            existing.Payload = payload;
            existing.ExpiresAtUtc = now + lifetime;
        }

        database.SaveChanges();
        SweepIfDue(database, now);
    }

    public async Task SetAsync(
        string purpose,
        string key,
        byte[] payload,
        TimeSpan lifetime,
        CancellationToken cancellationToken = default)
    {
        var storageKey = StorageKey(purpose, key);
        await using var database = await databaseFactory.CreateDbContextAsync(
            cancellationToken);
        var now = _timeProvider.GetUtcNow().UtcDateTime;

        var existing = await database.ProtocolStateEntries.FindAsync(
            [storageKey],
            cancellationToken);
        if (existing is null)
        {
            database.ProtocolStateEntries.Add(new ProtocolStateEntry
            {
                Key = storageKey,
                Purpose = purpose,
                Payload = payload,
                ExpiresAtUtc = now + lifetime,
            });
        }
        else
        {
            existing.Purpose = purpose;
            existing.Payload = payload;
            existing.ExpiresAtUtc = now + lifetime;
        }

        await database.SaveChangesAsync(cancellationToken);
        await SweepIfDueAsync(database, now, cancellationToken);
    }

    public void Remove(string purpose, string key)
    {
        var storageKey = StorageKey(purpose, key);
        using var database = databaseFactory.CreateDbContext();
        database.ProtocolStateEntries
            .Where(entry => entry.Key == storageKey)
            .ExecuteDelete();
    }

    public async Task RemoveAsync(
        string purpose,
        string key,
        CancellationToken cancellationToken = default)
    {
        var storageKey = StorageKey(purpose, key);
        await using var database = await databaseFactory.CreateDbContextAsync(
            cancellationToken);
        await database.ProtocolStateEntries
            .Where(entry => entry.Key == storageKey)
            .ExecuteDeleteAsync(cancellationToken);
    }

    // An expired row is treated as absent and left for the sweep: the caller is
    // asking whether the state is usable, and deleting it here would turn every
    // read into a write.
    private byte[]? Unexpired(ProtocolStateEntry? entry) =>
        entry is not null && entry.ExpiresAtUtc > _timeProvider.GetUtcNow().UtcDateTime
            ? entry.Payload
            : null;

    private void SweepIfDue(AppDbContext database, DateTime now)
    {
        if (Interlocked.Increment(ref _cleanupCounter) % CleanupInterval != 0)
        {
            return;
        }

        database.ProtocolStateEntries
            .Where(entry => entry.ExpiresAtUtc <= now)
            .ExecuteDelete();
    }

    private async Task SweepIfDueAsync(
        AppDbContext database,
        DateTime now,
        CancellationToken cancellationToken)
    {
        if (Interlocked.Increment(ref _cleanupCounter) % CleanupInterval != 0)
        {
            return;
        }

        await database.ProtocolStateEntries
            .Where(entry => entry.ExpiresAtUtc <= now)
            .ExecuteDeleteAsync(cancellationToken);
    }

    /// <summary>
    /// Hashes purpose + key into the stored identifier. The raw key can be a
    /// nonce partition or a ceremony identifier, so it is never written to the
    /// table in the clear, and hashing also bounds the column width regardless
    /// of what a caller passes.
    /// </summary>
    private static string StorageKey(string purpose, string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        return Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(purpose + "" + key)));
    }
}
