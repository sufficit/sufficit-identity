using System.Collections.Concurrent;

namespace Sufficit.Identity.STS.Ciba;

/// <summary>
/// Store for pending CIBA Core 1.0 authentication requests. Maps an
/// <c>auth_req_id</c> to the state needed by the initiation endpoint, the
/// completion channel, and the poll handler.
/// </summary>
/// <remarks>
/// <b>Backing store.</b> The registered implementation is
/// <see cref="RollingCibaPendingRequestStore"/>, which uses
/// <see cref="DatabaseCibaPendingRequestStore"/> as the primary (durable and
/// therefore shared across replicas) and mirrors into
/// <see cref="DistributedCibaPendingRequestStore"/> during the rolling
/// upgrade. <see cref="InMemoryCibaPendingRequestStore"/> below is a
/// single-process implementation retained for tests and embedded scenarios; it
/// is NOT what the STS composition registers.
/// <para>This remark previously claimed an in-memory store was shipped for a
/// single-instance deployment. That was stale (it predates the database store)
/// and it produced a false positive in the 2026-08-30 evaluation, which read
/// this comment instead of the DI registration. Corrected per the standing rule
/// that code — here <c>ServiceCollectionExtensions</c> — is the source of
/// truth.</para>
/// Entries self-evict on read after their expiry, so an abandoned request does
/// not accumulate.
/// </remarks>
public interface ICibaPendingRequestStore
{
    /// <summary>Stores a new pending request and returns the stored record.</summary>
    CibaPendingRequest Create(string clientId, string subject, IReadOnlyCollection<string> scopes, string? bindingMessage, TimeSpan lifetime);

    /// <summary>Looks up a pending request by auth_req_id. Returns null if
    /// unknown or expired (expired entries are evicted on read).</summary>
    CibaPendingRequest? Find(string authReqId);

    /// <summary>Marks the request approved by <paramref name="approvingSubject"/>.
    /// Returns false if the request is gone (expired/unknown).</summary>
    bool Approve(string authReqId, string approvingSubject);

    /// <summary>Marks the request denied. Returns false if gone.</summary>
    bool Deny(string authReqId);

    /// <summary>
    /// Atomically consumes an approved request. Only one concurrent poll may
    /// receive the approved record; subsequent polls observe the request as
    /// unknown/expired and cannot mint a second token.
    /// </summary>
    bool TryConsumeApproved(string authReqId, out CibaPendingRequest request);

    /// <summary>Records a poll timestamp for slow-down enforcement. Returns
    /// false if the client polled too soon (caller should return slow_down).</summary>
    bool TryRecordPoll(string authReqId, TimeSpan minimumInterval);
}

/// <summary>
/// The state of a pending CIBA request.
/// </summary>
public sealed record CibaPendingRequest(
    string AuthReqId,
    string ClientId,
    string Subject,
    IReadOnlyCollection<string> Scopes,
    string? BindingMessage,
    DateTimeOffset ExpiresAt,
    DateTimeOffset CreatedAt,
    DateTimeOffset LastPollAt,
    string? ApprovedSubject);

internal sealed class InMemoryCibaPendingRequestStore : ICibaPendingRequestStore
{
    private readonly ConcurrentDictionary<string, CibaPendingRequest> _requests = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;

    public InMemoryCibaPendingRequestStore(TimeProvider? timeProvider = null)
        => _timeProvider = timeProvider ?? TimeProvider.System;

    public CibaPendingRequest Create(string clientId, string subject, IReadOnlyCollection<string> scopes, string? bindingMessage, TimeSpan lifetime)
    {
        var now = _timeProvider.GetUtcNow();
        var request = new CibaPendingRequest(
            AuthReqId: CibaIdentifier.Create(),
            ClientId: clientId,
            Subject: subject,
            Scopes: scopes,
            BindingMessage: bindingMessage,
            ExpiresAt: now + lifetime,
            CreatedAt: now,
            LastPollAt: now,
            ApprovedSubject: null);
        _requests[request.AuthReqId] = request;
        return request;
    }

    public CibaPendingRequest? Find(string authReqId)
    {
        if (!_requests.TryGetValue(authReqId, out var request)) return null;
        if (request.ExpiresAt < _timeProvider.GetUtcNow())
        {
            _requests.TryRemove(authReqId, out _);
            return null;
        }
        return request;
    }

    public bool Approve(string authReqId, string approvingSubject)
    {
        if (!_requests.TryGetValue(authReqId, out var existing)) return false;
        _requests[authReqId] = existing with { ApprovedSubject = approvingSubject };
        return true;
    }

    public bool Deny(string authReqId)
    {
        return _requests.TryRemove(authReqId, out _);
    }

    public bool TryConsumeApproved(string authReqId, out CibaPendingRequest request)
    {
        request = null!;
        if (!_requests.TryGetValue(authReqId, out var existing)
            || string.IsNullOrEmpty(existing.ApprovedSubject))
        {
            return false;
        }

        if (_requests.TryRemove(
                new KeyValuePair<string, CibaPendingRequest>(authReqId, existing)))
        {
            request = existing;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Records a poll and returns whether the client waited long enough.
    /// Returns <c>false</c> if the request is unknown, OR if the client polled
    /// before <paramref name="minimumInterval"/> elapsed (slow_down). Returns
    /// <c>true</c> only when the poll is accepted (interval respected).
    /// </summary>
    public bool TryRecordPoll(string authReqId, TimeSpan minimumInterval)
    {
        if (!_requests.TryGetValue(authReqId, out var existing)) return false;
        var now = _timeProvider.GetUtcNow();
        if (now - existing.LastPollAt < minimumInterval)
        {
            // Too soon — do not refresh LastPollAt, so the window keeps counting
            // from the last accepted poll. The caller returns slow_down.
            return false;
        }
        _requests[authReqId] = existing with { LastPollAt = now };
        return true;
    }
}
