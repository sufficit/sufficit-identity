using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.STS.Ciba;

internal sealed class DatabaseCibaPendingRequestStore(
    IDbContextFactory<AppDbContext> databaseFactory,
    TimeProvider? timeProvider = null) : ICibaPendingRequestStore
{
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public CibaPendingRequest Create(
        string clientId,
        string subject,
        IReadOnlyCollection<string> scopes,
        string? bindingMessage,
        TimeSpan lifetime)
    {
        var now = _timeProvider.GetUtcNow();
        var request = new CibaPendingRequest(
            Guid.NewGuid().ToString("N"), clientId, subject, scopes,
            bindingMessage, now + lifetime, now, now, null);
        using var database = databaseFactory.CreateDbContext();
        database.CibaPendingStates.Add(ToEntity(request));
        database.SaveChanges();
        return request;
    }

    public CibaPendingRequest? Find(string authReqId)
    {
        using var database = databaseFactory.CreateDbContext();
        var now = _timeProvider.GetUtcNow().UtcDateTime;
        var entity = database.CibaPendingStates.AsNoTracking()
            .FirstOrDefault(item => item.AuthReqId == authReqId
                && (item.State == "pending" || item.State == "approved")
                && item.ExpiresAtUtc > now);
        return entity is null ? null : ToRecord(entity);
    }

    public bool Approve(string authReqId, string approvingSubject)
    {
        using var database = databaseFactory.CreateDbContext();
        var now = _timeProvider.GetUtcNow().UtcDateTime;
        return database.CibaPendingStates
            .Where(item => item.AuthReqId == authReqId
                && item.State == "pending"
                && item.ExpiresAtUtc > now)
            .ExecuteUpdate(setters => setters
                .SetProperty(item => item.State, "approved")
                .SetProperty(item => item.ApprovedSubject, approvingSubject)) == 1;
    }

    public bool Deny(string authReqId)
    {
        using var database = databaseFactory.CreateDbContext();
        return database.CibaPendingStates
            .Where(item => item.AuthReqId == authReqId
                && (item.State == "pending" || item.State == "approved"))
            .ExecuteUpdate(setters => setters
                .SetProperty(item => item.State, "denied")) == 1;
    }

    public bool TryConsumeApproved(
        string authReqId,
        out CibaPendingRequest request)
    {
        request = null!;
        var consumptionId = Guid.NewGuid().ToString("N");
        using var database = databaseFactory.CreateDbContext();
        var now = _timeProvider.GetUtcNow().UtcDateTime;
        var affected = database.CibaPendingStates
            .Where(item => item.AuthReqId == authReqId
                && item.State == "approved"
                && item.ExpiresAtUtc > now)
            .ExecuteUpdate(setters => setters
                .SetProperty(item => item.State, "consumed")
                .SetProperty(item => item.ConsumptionId, consumptionId));
        if (affected != 1) return false;

        var claimed = database.CibaPendingStates.AsNoTracking()
            .Single(item => item.ConsumptionId == consumptionId);
        request = ToRecord(claimed);
        return true;
    }

    public bool TryRecordPoll(string authReqId, TimeSpan minimumInterval)
    {
        using var database = databaseFactory.CreateDbContext();
        var now = _timeProvider.GetUtcNow().UtcDateTime;
        var latestAllowedPoll = now - minimumInterval;
        return database.CibaPendingStates
            .Where(item => item.AuthReqId == authReqId
                && item.State == "pending"
                && item.ExpiresAtUtc > now
                && item.LastPollAtUtc <= latestAllowedPoll)
            .ExecuteUpdate(setters => setters
                .SetProperty(item => item.LastPollAtUtc, now)) == 1;
    }

    internal void Import(CibaPendingRequest request)
    {
        using var database = databaseFactory.CreateDbContext();
        if (!database.CibaPendingStates.Any(item => item.AuthReqId == request.AuthReqId))
        {
            database.CibaPendingStates.Add(ToEntity(request));
            try
            {
                database.SaveChanges();
            }
            catch (DbUpdateException)
            {
                database.ChangeTracker.Clear();
            }
        }

        if (!string.IsNullOrWhiteSpace(request.ApprovedSubject))
            database.CibaPendingStates
                .Where(item => item.AuthReqId == request.AuthReqId
                    && item.State == "pending")
                .ExecuteUpdate(setters => setters
                    .SetProperty(item => item.State, "approved")
                    .SetProperty(item => item.ApprovedSubject, request.ApprovedSubject));
    }

    private static CibaPendingState ToEntity(CibaPendingRequest request) => new()
    {
        AuthReqId = request.AuthReqId,
        ClientId = request.ClientId,
        Subject = request.Subject,
        ScopesJson = JsonSerializer.Serialize(request.Scopes),
        BindingMessage = request.BindingMessage,
        ExpiresAtUtc = request.ExpiresAt.UtcDateTime,
        CreatedAtUtc = request.CreatedAt.UtcDateTime,
        LastPollAtUtc = request.LastPollAt.UtcDateTime,
        ApprovedSubject = request.ApprovedSubject,
        State = request.ApprovedSubject is null ? "pending" : "approved",
    };

    private static CibaPendingRequest ToRecord(CibaPendingState entity) => new(
        entity.AuthReqId,
        entity.ClientId,
        entity.Subject,
        JsonSerializer.Deserialize<string[]>(entity.ScopesJson) ?? [],
        entity.BindingMessage,
        new DateTimeOffset(entity.ExpiresAtUtc, TimeSpan.Zero),
        new DateTimeOffset(entity.CreatedAtUtc, TimeSpan.Zero),
        new DateTimeOffset(entity.LastPollAtUtc, TimeSpan.Zero),
        entity.ApprovedSubject);
}

internal sealed class RollingCibaPendingRequestStore(
    DatabaseCibaPendingRequestStore database,
    DistributedCibaPendingRequestStore legacy) : ICibaPendingRequestStore
{
    public CibaPendingRequest Create(
        string clientId,
        string subject,
        IReadOnlyCollection<string> scopes,
        string? bindingMessage,
        TimeSpan lifetime)
    {
        var request = database.Create(
            clientId, subject, scopes, bindingMessage, lifetime);
        legacy.Upsert(request);
        return request;
    }

    public CibaPendingRequest? Find(string authReqId)
    {
        Synchronize(authReqId);
        return database.Find(authReqId);
    }

    public bool Approve(string authReqId, string approvingSubject)
    {
        var databaseResult = database.Approve(authReqId, approvingSubject);
        var legacyResult = legacy.Approve(authReqId, approvingSubject);
        return databaseResult || legacyResult;
    }

    public bool Deny(string authReqId)
    {
        var databaseResult = database.Deny(authReqId);
        var legacyResult = legacy.Deny(authReqId);
        return databaseResult || legacyResult;
    }

    public bool TryConsumeApproved(
        string authReqId,
        out CibaPendingRequest request)
    {
        Synchronize(authReqId);
        if (!database.TryConsumeApproved(authReqId, out request)) return false;
        legacy.Deny(authReqId);
        return true;
    }

    public bool TryRecordPoll(string authReqId, TimeSpan minimumInterval)
    {
        Synchronize(authReqId);
        var result = database.TryRecordPoll(authReqId, minimumInterval);
        legacy.TryRecordPoll(authReqId, minimumInterval);
        return result;
    }

    private void Synchronize(string authReqId)
    {
        var legacyRequest = legacy.Find(authReqId);
        if (legacyRequest is not null) database.Import(legacyRequest);
    }
}
