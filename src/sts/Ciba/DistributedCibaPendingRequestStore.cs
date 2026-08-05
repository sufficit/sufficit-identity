using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;

namespace Sufficit.Identity.STS.Ciba;

/// <summary>
/// <see cref="IDistributedCache"/>-backed CIBA pending-request store. Survives
/// process restarts and is visible to every replica when the distributed cache
/// is shared (Redis, SQL Server). The default <c>AddDistributedMemoryCache</c>
/// provides a single-node in-process fallback that is still swappable.
/// </summary>
/// <remarks>
/// <b>Atomicity.</b> <see cref="TryConsumeApproved"/> uses a separate "consumed"
/// cache key as a marker so that only one concurrent poll wins. There is a
/// narrow window between the read of the approved record and the write of the
/// consumed marker where two polls on different replicas could both observe the
/// approved state. For a strict single-token guarantee under high concurrency,
/// swap the backing cache for one that supports atomic compare-and-swap
/// (Redis SETNX, SQL row locks). The current approach bounds the blast radius
/// to a single extra token (revocable via introspection), which is the same
/// graceful-degradation posture documented for the DPoP jti cache.
/// </remarks>
internal sealed class DistributedCibaPendingRequestStore : ICibaPendingRequestStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = null,
    };

    private const string KeyPrefix = "ciba:pending:";
    private const string ConsumedKeyPrefix = "ciba:consumed:";

    private readonly Microsoft.Extensions.Caching.Distributed.IDistributedCache _cache;
    private readonly TimeProvider _timeProvider;

    public DistributedCibaPendingRequestStore(
        Microsoft.Extensions.Caching.Distributed.IDistributedCache cache,
        TimeProvider? timeProvider = null)
    {
        _cache = cache;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public CibaPendingRequest Create(
        string clientId,
        string subject,
        IReadOnlyCollection<string> scopes,
        string? bindingMessage,
        TimeSpan lifetime)
    {
        var now = _timeProvider.GetUtcNow();
        var request = new CibaPendingRequest(
            AuthReqId: Guid.NewGuid().ToString("N"),
            ClientId: clientId,
            Subject: subject,
            Scopes: scopes,
            BindingMessage: bindingMessage,
            ExpiresAt: now + lifetime,
            CreatedAt: now,
            LastPollAt: now,
            ApprovedSubject: null);

        SetEntry(request, lifetime);
        return request;
    }

    public CibaPendingRequest? Find(string authReqId)
    {
        var entry = GetEntry(authReqId);
        if (entry is null) return null;
        if (entry.ExpiresAt < _timeProvider.GetUtcNow())
        {
            _cache.Remove(Key(authReqId));
            return null;
        }
        return entry;
    }

    public bool Approve(string authReqId, string approvingSubject)
    {
        var existing = GetEntry(authReqId);
        if (existing is null) return false;
        var updated = existing with { ApprovedSubject = approvingSubject };
        var remaining = existing.ExpiresAt - _timeProvider.GetUtcNow();
        if (remaining <= TimeSpan.Zero) return false;
        SetEntry(updated, remaining);
        return true;
    }

    public bool Deny(string authReqId)
    {
        var existed = GetEntry(authReqId) is not null;
        _cache.Remove(Key(authReqId));
        _cache.Remove(ConsumedKey(authReqId));
        return existed;
    }

    public bool TryConsumeApproved(string authReqId, out CibaPendingRequest request)
    {
        request = null!;
        var existing = GetEntry(authReqId);
        if (existing is null || string.IsNullOrEmpty(existing.ApprovedSubject))
        {
            return false;
        }

        // Marker-based consume: write a "consumed" key with the remaining TTL.
        // A second poll on any replica will see the marker and fail. This is
        // not a true atomic CAS, but it bounds double-issuance to the narrow
        // window described in the class remarks.
        var consumedKey = ConsumedKey(authReqId);
        var consumedMarker = _cache.GetString(consumedKey);
        if (consumedMarker is not null)
        {
            // Already consumed by another poll.
            return false;
        }

        var remaining = existing.ExpiresAt - _timeProvider.GetUtcNow();
        if (remaining <= TimeSpan.Zero) return false;

        _cache.SetString(consumedKey, "1", new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = remaining,
        });

        request = existing;
        // Clean up the main entry too.
        _cache.Remove(Key(authReqId));
        return true;
    }

    public bool TryRecordPoll(string authReqId, TimeSpan minimumInterval)
    {
        var existing = GetEntry(authReqId);
        if (existing is null) return false;
        var now = _timeProvider.GetUtcNow();
        if (now - existing.LastPollAt < minimumInterval)
        {
            return false;
        }
        var updated = existing with { LastPollAt = now };
        var remaining = existing.ExpiresAt - now;
        if (remaining > TimeSpan.Zero)
        {
            SetEntry(updated, remaining);
        }
        return true;
    }

    private static string Key(string authReqId) => KeyPrefix + authReqId;
    private static string ConsumedKey(string authReqId) => ConsumedKeyPrefix + authReqId;

    private CibaPendingRequest? GetEntry(string authReqId)
    {
        var json = _cache.GetString(Key(authReqId));
        if (string.IsNullOrEmpty(json)) return null;
        try
        {
            return JsonSerializer.Deserialize<CibaPendingRequest>(json, JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    private void SetEntry(CibaPendingRequest request, TimeSpan ttl)
    {
        var json = JsonSerializer.Serialize(request, JsonOptions);
        _cache.SetString(Key(request.AuthReqId), json, new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = ttl,
        });
    }
}
