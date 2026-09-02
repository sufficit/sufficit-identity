using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Audit;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Users;

internal sealed partial class UserManagementService
{
    public async Task<ManagementUserAccess> GetAccessAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var resource = new ManagementResource(
            ManagementResourceTypes.UserCollection);
        var readDecision = await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.UsersRead,
            resource,
            cancellationToken);
        if (!readDecision.IsAllowed)
        {
            throw new ManagementAccessException(readDecision);
        }

        var createDecision = await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.UsersCreate,
            resource,
            cancellationToken);

        return new ManagementUserAccess(
            CanRead: true,
            CanCreate: createDecision.IsAllowed);
    }

    public async Task<ManagementUserPage> SearchAsync(
        ManagementUserSearch query,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        var page = Math.Max(query.Page, 1);
        var pageSize = Math.Clamp(query.PageSize, 1, 100);
        var resource = new ManagementResource(
            ManagementResourceTypes.UserCollection);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.UsersRead,
            resource,
            cancellationToken);

        var users = database.Users.AsNoTracking();
        var now = DateTimeOffset.UtcNow;

        var search = query.Search?.Trim();
        if (!string.IsNullOrWhiteSpace(search))
        {
            users = users.Where(user =>
                user.UserName != null && user.UserName.Contains(search)
                || user.Email != null && user.Email.Contains(search));
        }

        users = query.State switch
        {
            ManagementUserStateFilter.Active => users.Where(user =>
                user.LockoutEnd == null || user.LockoutEnd <= now),
            ManagementUserStateFilter.Locked => users.Where(user =>
                user.LockoutEnd != null && user.LockoutEnd > now),
            _ => users,
        };
        users = query.EmailConfirmed switch
        {
            ManagementUserBooleanFilter.Enabled => users.Where(user => user.EmailConfirmed),
            ManagementUserBooleanFilter.Disabled => users.Where(user => !user.EmailConfirmed),
            _ => users,
        };
        users = query.Mfa switch
        {
            ManagementUserBooleanFilter.Enabled => users.Where(user => user.TwoFactorEnabled),
            ManagementUserBooleanFilter.Disabled => users.Where(user => !user.TwoFactorEnabled),
            _ => users,
        };

        var staleUnverifiedCutoff = DateTime.UtcNow.AddDays(-15);
        var staleUnverifiedWithoutExternal = database.Users
            .Where(user =>
                !user.EmailConfirmed
                && user.CreatedAtUtc < staleUnverifiedCutoff
                && !database.UserLogins.Any(login => login.UserId == user.Id));
        var staleUnverifiedWithoutExternalTotal = await
            staleUnverifiedWithoutExternal.CountAsync(cancellationToken);

        if (query.Review is ManagementUserReviewFilter.StaleUnverifiedWithoutExternal)
        {
            users = users.Where(user =>
                !user.EmailConfirmed
                && user.CreatedAtUtc < staleUnverifiedCutoff
                && !database.UserLogins.Any(login => login.UserId == user.Id));
        }

        var analyticsDays = Math.Clamp(query.AnalyticsDays, 7, 120);
        var today = DateTime.UtcNow.Date;
        var analyticsStart = today.AddDays(-(analyticsDays - 1));
        var analyticsEnd = today.AddDays(1);
        var dailyRows = await users
            .Where(user => user.CreatedAtUtc >= analyticsStart &&
                user.CreatedAtUtc < analyticsEnd)
            .GroupBy(user => user.CreatedAtUtc.Date)
            .Select(group => new { Date = group.Key, Count = group.Count() })
            .ToArrayAsync(cancellationToken);
        var dailyCounts = dailyRows.ToDictionary(row => row.Date, row => row.Count);
        var counts = Enumerable.Range(0, analyticsDays)
            .Select(offset => dailyCounts.GetValueOrDefault(analyticsStart.AddDays(offset)))
            .ToArray();
        var median = Median(counts);
        var deviations = counts.Select(value => Math.Abs(value - median)).ToArray();
        var mad = Median(deviations);
        var anomalyThreshold = Math.Max(3,
            (int)Math.Ceiling(median + 3m * Math.Max(1m, 1.4826m * mad)));
        var days = Enumerable.Range(0, analyticsDays)
            .Select(offset =>
            {
                var date = analyticsStart.AddDays(offset);
                var count = dailyCounts.GetValueOrDefault(date);
                return new ManagementUserRegistrationDay(
                    DateOnly.FromDateTime(date), count, count > anomalyThreshold);
            })
            .ToArray();

        var registeredToday = dailyCounts.GetValueOrDefault(today);
        var directoryTotal = await database.Users.CountAsync(cancellationToken);

        if (query.RegisteredOn is { } registeredOn)
        {
            var start = registeredOn.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc);
            users = users.Where(user => user.CreatedAtUtc >= start &&
                user.CreatedAtUtc < start.AddDays(1));
        }
        else
        {
            if (query.RegisteredFrom is { } from)
            {
                var start = from.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc);
                users = users.Where(user => user.CreatedAtUtc >= start);
            }
            if (query.RegisteredTo is { } to)
            {
                var end = to.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc).AddDays(1);
                users = users.Where(user => user.CreatedAtUtc < end);
            }
        }

        var totalCount = await users.CountAsync(cancellationToken);
        var orderedUsers = query.Sort switch
        {
            ManagementUserSort.CreatedOldest => users
                .OrderBy(user => user.CreatedAtUtc).ThenBy(user => user.Id),
            ManagementUserSort.NameAscending => users
                .OrderBy(user => user.UserName ?? user.Email ?? user.Id).ThenBy(user => user.Id),
            ManagementUserSort.NameDescending => users
                .OrderByDescending(user => user.UserName ?? user.Email ?? user.Id).ThenBy(user => user.Id),
            ManagementUserSort.EmailAscending => users
                .OrderBy(user => user.Email ?? user.UserName ?? user.Id).ThenBy(user => user.Id),
            ManagementUserSort.EmailDescending => users
                .OrderByDescending(user => user.Email ?? user.UserName ?? user.Id).ThenBy(user => user.Id),
            _ => users.OrderByDescending(user => user.CreatedAtUtc).ThenBy(user => user.Id),
        };
        var pageRows = await orderedUsers
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(user => new
            {
                user.Id,
                user.UserName,
                user.Email,
                user.EmailConfirmed,
                user.TwoFactorEnabled,
                user.CreatedAtUtc,
                HasExternalLogin = database.UserLogins.Any(login =>
                    login.UserId == user.Id),
                // Correlated subquery rather than a join: the claim is absent
                // for almost every account, and a join would drop or duplicate
                // rows depending on its shape.
                PictureUrl = database.UserClaims
                    .Where(claim => claim.UserId == user.Id
                        && claim.ClaimType == "picture")
                    .Select(claim => claim.ClaimValue)
                    .FirstOrDefault(),
                IsLockedOut = user.LockoutEnd != null
                    && user.LockoutEnd > now
            })
            .ToArrayAsync(cancellationToken);
        var items = pageRows
            .Select(user => new ManagementUserSummary(
                user.Id,
                user.UserName,
                user.Email,
                user.EmailConfirmed,
                user.TwoFactorEnabled,
                user.IsLockedOut,
                user.CreatedAtUtc,
                user.HasExternalLogin,
                AvatarPictureHosts.Normalize(
                    user.PictureUrl,
                    managementOptions.Value.AvatarPictureOrigins)))
            .ToArray();

        // L3 fix (eval): no per-page audit row on read/list paths — the
        // transport access log already records who queried what. Audit stays
        // focused on state-changing operations (write/delete/update/reset).

        return new ManagementUserPage(
            items,
            page,
            pageSize,
            totalCount,
            new ManagementUserAnalytics(
                directoryTotal,
                totalCount,
                registeredToday,
                median,
                anomalyThreshold,
                days,
                staleUnverifiedWithoutExternalTotal));
    }

    public async Task<ManagementUserDetail> GetAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        var resource = new ManagementResource(
            ManagementResourceTypes.User,
            id);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.UsersRead,
            resource,
            cancellationToken);

        var user = await database.Users
            .AsNoTracking()
            .Where(user => user.Id == id)
            .Select(user => new
            {
                user.Id,
                user.UserName,
                user.Email,
                user.EmailConfirmed,
                user.PhoneNumber,
                user.PhoneNumberConfirmed,
                user.TwoFactorEnabled,
                user.LockoutEnabled,
                user.LockoutEnd,
                user.AccessFailedCount,
                user.Timestamp
            })
            .FirstOrDefaultAsync(cancellationToken);
        if (user is null)
        {
            await WriteAuditAsync(
                context,
                ManagementCapabilities.UsersRead,
                resource,
                decision,
                "not-found",
                "user_not_found",
                cancellationToken);
            throw new ManagementNotFoundException(
                "user_not_found",
                "The user was not found.");
        }

        var resetDecision = await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.UsersReset,
            resource,
            cancellationToken);
        var isLockedOut = user.LockoutEnd is { } lockoutEnd
            && lockoutEnd > DateTimeOffset.UtcNow;
        var lockoutDecision = await EvaluateLockoutChangeAsync(
            user.Id,
            context,
            locking: !isLockedOut,
            cancellationToken);
        var updateProfileDecision = await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.UsersUpdate,
            resource,
            cancellationToken);
        var deleteDecision = await EvaluateDeleteAsync(
            user.Id,
            context,
            cancellationToken);

        await WriteAuditAsync(
            context,
            ManagementCapabilities.UsersRead,
            resource,
            decision,
            "succeeded",
            "user_read",
            cancellationToken);

        return new ManagementUserDetail(
            user.Id,
            user.UserName,
            user.Email,
            user.EmailConfirmed,
            user.PhoneNumber,
            user.PhoneNumberConfirmed,
            user.TwoFactorEnabled,
            user.LockoutEnabled,
            user.LockoutEnd,
            user.AccessFailedCount,
            user.Timestamp,
            Actions(
                resetDecision,
                lockoutDecision,
                updateProfileDecision,
                deleteDecision));
    }

    private static decimal Median(IReadOnlyList<int> values)
    {
        if (values.Count == 0) return 0;
        var ordered = values.OrderBy(value => value).ToArray();
        var middle = ordered.Length / 2;
        return ordered.Length % 2 == 0
            ? (ordered[middle - 1] + ordered[middle]) / 2m
            : ordered[middle];
    }
}
