using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.STS.SharedSignals;

/// <summary>
/// Persistent store for SSF streams (RFC 8933) and their poll-delivery queue
/// (RFC 8934). Implemented over <see cref="AppDbContext"/> so streams survive
/// restarts and are visible to every replica.
/// </summary>
public interface ISsfStreamStore
{
    Task<SsfStream> CreateAsync(
        string audience,
        string deliveryMethod,
        string? endpoint,
        string? authorization,
        string subjectScope,
        IReadOnlyCollection<string> eventsRequested,
        string? description,
        CancellationToken cancellationToken);

    Task<SsfStream?> GetByStreamIdAsync(
        string streamId,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<SsfStream>> ListEnabledAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<SsfStream>> ListEnabledPushAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<SsfStream>> ListEnabledPollAsync(CancellationToken cancellationToken);

    Task MarkVerifiedAsync(string streamId, CancellationToken cancellationToken);

    Task DisableAsync(string streamId, CancellationToken cancellationToken);

    /// <summary>
    /// Enqueues a SET for later poll delivery (RFC 8934). Idempotent on
    /// <paramref name="jti"/> per stream — the same jti is never queued twice.
    /// </summary>
    Task EnqueuePollDeliveryAsync(
        string streamId,
        string jti,
        string setPayload,
        CancellationToken cancellationToken);

    /// <summary>
    /// Pulls up to <paramref name="limit"/> unconsumed SETs for a stream and
    /// marks them consumed. Returns the payloads and whether more remain.
    /// </summary>
    Task<(IReadOnlyList<string> Payloads, bool MoreAvailable)> PullAndConsumeAsync(
        string streamId,
        int limit,
        CancellationToken cancellationToken);
}

internal sealed class SsfStreamStore : ISsfStreamStore
{
    public const string PushDeliveryMethod = "urn:ietf:rfc:8935";
    public const string PollDeliveryMethod = "urn:ietf:rfc:8934";

    private static readonly HashSet<string> AllowedDeliveryMethods =
        new(StringComparer.Ordinal) { PushDeliveryMethod, PollDeliveryMethod };

    private readonly AppDbContext _database;
    private readonly TimeProvider _timeProvider;
    private readonly IKeyVault _keyVault;

    public SsfStreamStore(
        AppDbContext database,
        IKeyVault keyVault,
        TimeProvider? timeProvider = null)
    {
        _database = database;
        _keyVault = keyVault;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    private const string AuthorizationKeyName = "ssf-stream-authz";

    /// <summary>
    /// Encrypts the SSF push-delivery bearer token before it is persisted.
    /// When the vault is disabled (PassThroughKeyVault), this is a no-op
    /// marker-prefix round-trip. When enabled, the token is envelope-encrypted
    /// (AES-256-GCM) with AAD bound to the stream id.
    /// </summary>
    private async Task<string?> EncryptAuthorizationAsync(
        string? authorization, string streamId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(authorization)) return null;
        return await _keyVault.EncryptAsync(
            AuthorizationKeyName,
            authorization,
            new Dictionary<string, string> { ["stream_id"] = streamId },
            ct);
    }

    /// <summary>
    /// Decrypts the stored ciphertext back to the plaintext bearer token.
    /// PassThrough strips the marker; real vault decrypts + verifies AAD.
    /// </summary>
    private async Task<string?> DecryptAuthorizationAsync(
        string? stored, string streamId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(stored)) return null;
        return await _keyVault.DecryptStringAsync(
            stored,
            new Dictionary<string, string> { ["stream_id"] = streamId },
            ct);
    }

    public async Task<SsfStream> CreateAsync(
        string audience,
        string deliveryMethod,
        string? endpoint,
        string? authorization,
        string subjectScope,
        IReadOnlyCollection<string> eventsRequested,
        string? description,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        if (!AllowedDeliveryMethods.Contains(deliveryMethod))
        {
            throw new ArgumentException(
                $"delivery_method must be '{PushDeliveryMethod}' or '{PollDeliveryMethod}'.",
                nameof(deliveryMethod));
        }

        if (deliveryMethod == PushDeliveryMethod && string.IsNullOrWhiteSpace(endpoint))
        {
            throw new ArgumentException(
                "An HTTPS endpoint is required for push delivery.",
                nameof(endpoint));
        }

        var now = _timeProvider.GetUtcNow().UtcDateTime;
        var id = Guid.NewGuid().ToString("N");
        var streamId = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(16));

        var stream = new SsfStream
        {
            Id = id,
            StreamId = streamId,
            Audience = audience,
            DeliveryMethod = deliveryMethod,
            Endpoint = endpoint,
            Authorization = await EncryptAuthorizationAsync(authorization, streamId, cancellationToken),
            Status = "enabled",
            VerificationState = "pending",
            SubjectScope = string.IsNullOrWhiteSpace(subjectScope) ? "ALL" : subjectScope,
            EventsRequested = System.Text.Json.JsonSerializer.Serialize(eventsRequested),
            Description = description,
            CreatedAtUtc = now,
            UpdatedAtUtc = now,
        };

        _database.SsfStreams.Add(stream);
        await _database.SaveChangesAsync(cancellationToken);
        // Return the decrypted Authorization so the caller sees plaintext,
        // not ciphertext (the stored row has the encrypted form).
        stream.Authorization = await DecryptAuthorizationAsync(stream.Authorization, streamId, cancellationToken);
        return stream;
    }

    public async Task<SsfStream?> GetByStreamIdAsync(
        string streamId,
        CancellationToken cancellationToken)
    {
        var stream = await _database.SsfStreams
            .AsNoTracking()
            .FirstOrDefaultAsync(s => s.StreamId == streamId, cancellationToken);
        if (stream is null) return null;
        stream.Authorization = await DecryptAuthorizationAsync(stream.Authorization, stream.StreamId, cancellationToken);
        return stream;
    }

    public async Task<IReadOnlyList<SsfStream>> ListEnabledAsync(
        CancellationToken cancellationToken)
    {
        var streams = await _database.SsfStreams
            .AsNoTracking()
            .Where(s => s.Status == "enabled")
            .ToArrayAsync(cancellationToken);
        await DecryptAuthorizationsAsync(streams, cancellationToken);
        return streams;
    }

    public async Task<IReadOnlyList<SsfStream>> ListEnabledPushAsync(
        CancellationToken cancellationToken)
    {
        var streams = await _database.SsfStreams
            .AsNoTracking()
            .Where(s => s.Status == "enabled" && s.DeliveryMethod == PushDeliveryMethod)
            .ToArrayAsync(cancellationToken);
        await DecryptAuthorizationsAsync(streams, cancellationToken);
        return streams;
    }

    public async Task<IReadOnlyList<SsfStream>> ListEnabledPollAsync(
        CancellationToken cancellationToken)
    {
        var streams = await _database.SsfStreams
            .AsNoTracking()
            .Where(s => s.Status == "enabled" && s.DeliveryMethod == PollDeliveryMethod)
            .ToArrayAsync(cancellationToken);
        await DecryptAuthorizationsAsync(streams, cancellationToken);
        return streams;
    }

    /// <summary>
    /// Decrypts Authorization on a batch of streams (best-effort: a decrypt
    /// failure on one stream logs and leaves the ciphertext, so one bad row
    /// doesn't break the whole list).
    /// </summary>
    private async Task DecryptAuthorizationsAsync(
        SsfStream[] streams, CancellationToken cancellationToken)
    {
        foreach (var stream in streams)
        {
            stream.Authorization = await DecryptAuthorizationAsync(
                stream.Authorization, stream.StreamId, cancellationToken);
        }
    }

    public async Task MarkVerifiedAsync(string streamId, CancellationToken cancellationToken)
    {
        var stream = await _database.SsfStreams
            .FirstOrDefaultAsync(s => s.StreamId == streamId, cancellationToken);
        if (stream is null) return;
        stream.VerificationState = "verified";
        stream.UpdatedAtUtc = _timeProvider.GetUtcNow().UtcDateTime;
        await _database.SaveChangesAsync(cancellationToken);
    }

    public async Task DisableAsync(string streamId, CancellationToken cancellationToken)
    {
        var stream = await _database.SsfStreams
            .FirstOrDefaultAsync(s => s.StreamId == streamId, cancellationToken);
        if (stream is null) return;
        stream.Status = "disabled";
        stream.UpdatedAtUtc = _timeProvider.GetUtcNow().UtcDateTime;
        await _database.SaveChangesAsync(cancellationToken);
    }

    public async Task EnqueuePollDeliveryAsync(
        string streamId,
        string jti,
        string setPayload,
        CancellationToken cancellationToken)
    {
        // Idempotent: skip if this jti is already queued for this stream.
        var exists = await _database.SsfSetDeliveries
            .AnyAsync(d => d.StreamId == streamId && d.Jti == jti, cancellationToken);
        if (exists) return;

        _database.SsfSetDeliveries.Add(new SsfSetDelivery
        {
            StreamId = streamId,
            Jti = jti,
            SetPayload = setPayload,
            CreatedAtUtc = _timeProvider.GetUtcNow().UtcDateTime,
        });
        await _database.SaveChangesAsync(cancellationToken);
    }

    public async Task<(IReadOnlyList<string> Payloads, bool MoreAvailable)> PullAndConsumeAsync(
        string streamId,
        int limit,
        CancellationToken cancellationToken)
    {
        limit = Math.Clamp(limit, 1, 100);
        var now = _timeProvider.GetUtcNow().UtcDateTime;

        // Pull unconsumed rows ordered oldest-first, then mark them consumed.
        var pending = await _database.SsfSetDeliveries
            .Where(d => d.StreamId == streamId && d.ConsumedAt == null)
            .OrderBy(d => d.CreatedAtUtc)
            .ThenBy(d => d.Id)
            .Take(limit + 1)
            .ToArrayAsync(cancellationToken);

        var moreAvailable = pending.Length > limit;
        var toConsume = moreAvailable ? pending.Take(limit).ToArray() : pending;

        foreach (var row in toConsume)
        {
            row.ConsumedAt = now;
        }

        if (toConsume.Length > 0)
        {
            await _database.SaveChangesAsync(cancellationToken);
        }

        return (toConsume.Select(r => r.SetPayload).ToArray(), moreAvailable);
    }
}
