using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;

namespace Sufficit.Identity.Scim;

public interface IScimProvisioningService
{
    Task<ScimListResponse<ScimUserResource>> ListUsersAsync(
        string? filter,
        int startIndex,
        int count,
        ScimRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ScimUserResource> GetUserAsync(
        string id,
        ScimRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ScimUserResource> CreateUserAsync(
        ScimUserResource resource,
        ScimRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ScimUserResource> ReplaceUserAsync(
        string id,
        ScimUserResource resource,
        ScimRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ScimUserResource> PatchUserAsync(
        string id,
        ScimPatchRequest request,
        ScimRequestContext context,
        CancellationToken cancellationToken = default);

    Task DeleteUserAsync(
        string id,
        ScimRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ScimListResponse<ScimGroupResource>> ListGroupsAsync(
        string? filter,
        int startIndex,
        int count,
        ScimRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ScimGroupResource> GetGroupAsync(
        string id,
        ScimRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ScimGroupResource> CreateGroupAsync(
        ScimGroupResource resource,
        ScimRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ScimGroupResource> ReplaceGroupAsync(
        string id,
        ScimGroupResource resource,
        ScimRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ScimGroupResource> PatchGroupAsync(
        string id,
        ScimPatchRequest request,
        ScimRequestContext context,
        CancellationToken cancellationToken = default);

    Task DeleteGroupAsync(
        string id,
        ScimRequestContext context,
        CancellationToken cancellationToken = default);
}

internal sealed partial class ScimProvisioningService(
    AppDbContext database,
    UserManager<ApplicationUser> userManager,
    IIdentityAccountLifecycleService accountLifecycle,
    IOptions<ScimOptions> options,
    ILogger<ScimProvisioningService> logger) : IScimProvisioningService
{
    private static readonly JsonSerializerOptions PatchJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    [GeneratedRegex(
        "^(?<attribute>id|userName|externalId|displayName)\\s+eq\\s+\"(?<value>(?:\\\\.|[^\"])*)\"$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex EqualityFilterRegex();

    [GeneratedRegex(
        "^members\\s*\\[\\s*value\\s+eq\\s+\"(?<value>(?:\\\\.|[^\"])*)\"\\s*\\]$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MemberPathFilterRegex();

    public async Task<ScimListResponse<ScimUserResource>> ListUsersAsync(
        string? filter,
        int startIndex,
        int count,
        ScimRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var paging = Paging(startIndex, count);
        var query = ApplyUserFilter(
            database.Users.AsNoTracking(),
            filter);
        var total = await query.CountAsync(cancellationToken);
        var users = await query
            .OrderBy(user => user.UserName)
            .ThenBy(user => user.Id)
            .Skip(paging.Skip)
            .Take(paging.Count)
            .ToArrayAsync(cancellationToken);
        var resources = new List<ScimUserResource>(users.Length);
        foreach (var user in users)
        {
            resources.Add(await BuildUserAsync(user, cancellationToken));
        }

        AddAudit(
            context,
            "scim.users.read",
            "scim-user-collection",
            null,
            "succeeded",
            "scim_users_listed");
        await database.SaveChangesAsync(cancellationToken);

        return new ScimListResponse<ScimUserResource>
        {
            TotalResults = total,
            StartIndex = paging.StartIndex,
            ItemsPerPage = resources.Count,
            Resources = resources
        };
    }

    public async Task<ScimUserResource> GetUserAsync(
        string id,
        ScimRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var user = await database.Users
            .AsNoTracking()
            .SingleOrDefaultAsync(user => user.Id == id, cancellationToken)
            ?? throw ScimException.NotFound(
                $"SCIM user '{id}' was not found.");
        var resource = await BuildUserAsync(user, cancellationToken);

        AddAudit(
            context,
            "scim.users.read",
            "scim-user",
            id,
            "succeeded",
            "scim_user_read");
        await database.SaveChangesAsync(cancellationToken);
        return resource;
    }

    public async Task<ScimUserResource> CreateUserAsync(
        ScimUserResource resource,
        ScimRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);
        ValidateUserResource(resource);
        var email = PrimaryEmail(resource);
        var now = DateTime.UtcNow;
        var user = new ApplicationUser
        {
            UserName = resource.UserName.Trim(),
            Email = email,
            LockoutEnabled = true
        };

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            var created = string.IsNullOrEmpty(resource.Password)
                ? await userManager.CreateAsync(user)
                : await userManager.CreateAsync(user, resource.Password);
            EnsureIdentityResult(created);

            var profile = NewProfile(user.Id, resource, now);
            database.ScimUserProfiles.Add(profile);
            if (!resource.Active)
            {
                await accountLifecycle.SetActiveAsync(
                    user,
                    active: false,
                    cancellationToken);
            }

            AddAudit(
                context,
                "scim.users.write",
                "scim-user",
                user.Id,
                "succeeded",
                "scim_user_created");
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is not ScimException)
        {
            await RollbackAsync(transaction);
            logger.LogError(
                exception,
                "SCIM user creation failed. CorrelationId={CorrelationId}",
                context.CorrelationId);
            throw ScimException.Conflict(
                "The SCIM user could not be created.");
        }
        catch
        {
            await RollbackAsync(transaction);
            throw;
        }

        return await GetUserWithoutAuditAsync(user.Id, cancellationToken);
    }

    public async Task<ScimUserResource> ReplaceUserAsync(
        string id,
        ScimUserResource resource,
        ScimRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);
        ValidateUserResource(resource);
        var user = await userManager.FindByIdAsync(id)
            ?? throw ScimException.NotFound(
                $"SCIM user '{id}' was not found.");
        var email = PrimaryEmail(resource);

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            EnsureIdentityResult(
                await userManager.SetUserNameAsync(
                    user,
                    resource.UserName.Trim()));
            EnsureIdentityResult(
                await userManager.SetEmailAsync(user, email));

            if (!string.IsNullOrEmpty(resource.Password))
            {
                var resetToken =
                    await userManager.GeneratePasswordResetTokenAsync(user);
                EnsureIdentityResult(
                    await userManager.ResetPasswordAsync(
                        user,
                        resetToken,
                        resource.Password));
            }

            await accountLifecycle.SetActiveAsync(
                user,
                resource.Active,
                cancellationToken);

            var profile = await database.ScimUserProfiles
                .SingleOrDefaultAsync(
                    value => value.UserId == id,
                    cancellationToken);
            if (profile is null)
            {
                profile = NewProfile(id, resource, DateTime.UtcNow);
                database.ScimUserProfiles.Add(profile);
            }
            else
            {
                ApplyProfile(profile, resource);
                profile.UpdatedAtUtc = DateTime.UtcNow;
            }

            AddAudit(
                context,
                "scim.users.write",
                "scim-user",
                id,
                "succeeded",
                "scim_user_replaced");
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is not ScimException)
        {
            await RollbackAsync(transaction);
            logger.LogError(
                exception,
                "SCIM user replacement failed for {UserId}. CorrelationId={CorrelationId}",
                id,
                context.CorrelationId);
            throw ScimException.Conflict(
                "The SCIM user could not be replaced.");
        }
        catch
        {
            await RollbackAsync(transaction);
            throw;
        }

        return await GetUserWithoutAuditAsync(id, cancellationToken);
    }

    public async Task<ScimUserResource> PatchUserAsync(
        string id,
        ScimPatchRequest request,
        ScimRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ValidatePatchRequest(request);
        var resource = await GetUserWithoutAuditAsync(id, cancellationToken);
        foreach (var operation in request.Operations)
        {
            ApplyUserPatch(resource, operation);
        }

        var replaced = await ReplaceUserAsync(
            id,
            resource,
            context,
            cancellationToken);
        return replaced;
    }

    public async Task DeleteUserAsync(
        string id,
        ScimRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var user = await userManager.FindByIdAsync(id)
            ?? throw ScimException.NotFound(
                $"SCIM user '{id}' was not found.");

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            await accountLifecycle.DeleteAsync(user, cancellationToken);
            AddAudit(
                context,
                "scim.users.write",
                "scim-user",
                id,
                "succeeded",
                "scim_user_deleted");
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is not ScimException)
        {
            await RollbackAsync(transaction);
            logger.LogError(
                exception,
                "SCIM user deletion failed for {UserId}. CorrelationId={CorrelationId}",
                id,
                context.CorrelationId);
            throw ScimException.Conflict(
                "The SCIM user could not be deleted.");
        }
        catch
        {
            await RollbackAsync(transaction);
            throw;
        }
    }

    public async Task<ScimListResponse<ScimGroupResource>> ListGroupsAsync(
        string? filter,
        int startIndex,
        int count,
        ScimRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var paging = Paging(startIndex, count);
        var query = ApplyGroupFilter(
            database.ScimGroups.AsNoTracking(),
            filter);
        var total = await query.CountAsync(cancellationToken);
        var groups = await query
            .OrderBy(group => group.DisplayName)
            .ThenBy(group => group.Id)
            .Skip(paging.Skip)
            .Take(paging.Count)
            .ToArrayAsync(cancellationToken);
        var resources = new List<ScimGroupResource>(groups.Length);
        foreach (var group in groups)
        {
            resources.Add(await BuildGroupAsync(group, cancellationToken));
        }

        AddAudit(
            context,
            "scim.groups.read",
            "scim-group-collection",
            null,
            "succeeded",
            "scim_groups_listed");
        await database.SaveChangesAsync(cancellationToken);

        return new ScimListResponse<ScimGroupResource>
        {
            TotalResults = total,
            StartIndex = paging.StartIndex,
            ItemsPerPage = resources.Count,
            Resources = resources
        };
    }

    public async Task<ScimGroupResource> GetGroupAsync(
        string id,
        ScimRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var resource = await GetGroupWithoutAuditAsync(id, cancellationToken);
        AddAudit(
            context,
            "scim.groups.read",
            "scim-group",
            id,
            "succeeded",
            "scim_group_read");
        await database.SaveChangesAsync(cancellationToken);
        return resource;
    }

    public async Task<ScimGroupResource> CreateGroupAsync(
        ScimGroupResource resource,
        ScimRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);
        ValidateGroupResource(resource);
        var now = DateTime.UtcNow;
        var group = new ScimGroup
        {
            Id = Guid.NewGuid().ToString("N"),
            ExternalId = NormalizeOptional(resource.ExternalId),
            DisplayName = resource.DisplayName.Trim(),
            CreatedAtUtc = now,
            UpdatedAtUtc = now,
            ConcurrencyStamp = Guid.NewGuid().ToString("N")
        };

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            database.ScimGroups.Add(group);
            await database.SaveChangesAsync(cancellationToken);
            await ReplaceGroupMembersAsync(
                group.Id,
                resource.Members,
                cancellationToken);
            AddAudit(
                context,
                "scim.groups.write",
                "scim-group",
                group.Id,
                "succeeded",
                "scim_group_created");
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is not ScimException)
        {
            await RollbackAsync(transaction);
            logger.LogError(
                exception,
                "SCIM group creation failed. CorrelationId={CorrelationId}",
                context.CorrelationId);
            throw ScimException.Conflict(
                "The SCIM group could not be created.");
        }
        catch
        {
            await RollbackAsync(transaction);
            throw;
        }

        return await GetGroupWithoutAuditAsync(group.Id, cancellationToken);
    }

    public async Task<ScimGroupResource> ReplaceGroupAsync(
        string id,
        ScimGroupResource resource,
        ScimRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);
        ValidateGroupResource(resource);
        var group = await database.ScimGroups
            .SingleOrDefaultAsync(group => group.Id == id, cancellationToken)
            ?? throw ScimException.NotFound(
                $"SCIM group '{id}' was not found.");

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            group.ExternalId = NormalizeOptional(resource.ExternalId);
            group.DisplayName = resource.DisplayName.Trim();
            group.UpdatedAtUtc = DateTime.UtcNow;
            group.ConcurrencyStamp = Guid.NewGuid().ToString("N");
            await ReplaceGroupMembersAsync(
                id,
                resource.Members,
                cancellationToken);
            AddAudit(
                context,
                "scim.groups.write",
                "scim-group",
                id,
                "succeeded",
                "scim_group_replaced");
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is not ScimException)
        {
            await RollbackAsync(transaction);
            logger.LogError(
                exception,
                "SCIM group replacement failed for {GroupId}. CorrelationId={CorrelationId}",
                id,
                context.CorrelationId);
            throw ScimException.Conflict(
                "The SCIM group could not be replaced.");
        }
        catch
        {
            await RollbackAsync(transaction);
            throw;
        }

        return await GetGroupWithoutAuditAsync(id, cancellationToken);
    }

    public async Task<ScimGroupResource> PatchGroupAsync(
        string id,
        ScimPatchRequest request,
        ScimRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ValidatePatchRequest(request);
        var resource = await GetGroupWithoutAuditAsync(
            id,
            cancellationToken);
        foreach (var operation in request.Operations)
        {
            ApplyGroupPatch(resource, operation);
        }

        return await ReplaceGroupAsync(
            id,
            resource,
            context,
            cancellationToken);
    }

    public async Task DeleteGroupAsync(
        string id,
        ScimRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var group = await database.ScimGroups
            .SingleOrDefaultAsync(group => group.Id == id, cancellationToken)
            ?? throw ScimException.NotFound(
                $"SCIM group '{id}' was not found.");

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            await database.ScimGroupGroupMembers
                .Where(member => member.MemberGroupId == id)
                .ExecuteDeleteAsync(cancellationToken);
            database.ScimGroups.Remove(group);
            AddAudit(
                context,
                "scim.groups.write",
                "scim-group",
                id,
                "succeeded",
                "scim_group_deleted");
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is not ScimException)
        {
            await RollbackAsync(transaction);
            logger.LogError(
                exception,
                "SCIM group deletion failed for {GroupId}. CorrelationId={CorrelationId}",
                id,
                context.CorrelationId);
            throw ScimException.Conflict(
                "The SCIM group could not be deleted.");
        }
        catch
        {
            await RollbackAsync(transaction);
            throw;
        }
    }

    private IQueryable<ApplicationUser> ApplyUserFilter(
        IQueryable<ApplicationUser> query,
        string? filter)
    {
        if (string.IsNullOrWhiteSpace(filter))
        {
            return query;
        }

        var parsed = ParseEqualityFilter(filter);
        return parsed.Attribute.ToLowerInvariant() switch
        {
            "id" => query.Where(user => user.Id == parsed.Value),
            "username" => query.Where(
                user => user.NormalizedUserName
                    == userManager.NormalizeName(parsed.Value)),
            "externalid" => query.Where(user =>
                database.ScimUserProfiles.Any(profile =>
                    profile.UserId == user.Id
                    && profile.ExternalId == parsed.Value)),
            _ => throw ScimException.BadRequest(
                $"Filtering by '{parsed.Attribute}' is not supported.",
                "invalidFilter")
        };
    }

    private static IQueryable<ScimGroup> ApplyGroupFilter(
        IQueryable<ScimGroup> query,
        string? filter)
    {
        if (string.IsNullOrWhiteSpace(filter))
        {
            return query;
        }

        var parsed = ParseEqualityFilter(filter);
        return parsed.Attribute.ToLowerInvariant() switch
        {
            "id" => query.Where(group => group.Id == parsed.Value),
            "externalid" => query.Where(
                group => group.ExternalId == parsed.Value),
            "displayname" => query.Where(
                group => group.DisplayName == parsed.Value),
            _ => throw ScimException.BadRequest(
                $"Filtering by '{parsed.Attribute}' is not supported.",
                "invalidFilter")
        };
    }

    private static (string Attribute, string Value) ParseEqualityFilter(
        string filter)
    {
        var match = EqualityFilterRegex().Match(filter.Trim());
        if (!match.Success)
        {
            throw ScimException.BadRequest(
                "Only the SCIM 'eq' operator is supported for id, userName, externalId and displayName.",
                "invalidFilter");
        }

        var encoded = $"\"{match.Groups["value"].Value}\"";
        return (
            match.Groups["attribute"].Value,
            JsonSerializer.Deserialize<string>(encoded)
                ?? string.Empty);
    }

    private async Task<ScimUserResource> GetUserWithoutAuditAsync(
        string id,
        CancellationToken cancellationToken)
    {
        var user = await database.Users
            .AsNoTracking()
            .SingleOrDefaultAsync(user => user.Id == id, cancellationToken)
            ?? throw ScimException.NotFound(
                $"SCIM user '{id}' was not found.");
        return await BuildUserAsync(user, cancellationToken);
    }

    private async Task<ScimUserResource> BuildUserAsync(
        ApplicationUser user,
        CancellationToken cancellationToken)
    {
        var profile = await database.ScimUserProfiles
            .AsNoTracking()
            .SingleOrDefaultAsync(
                value => value.UserId == user.Id,
                cancellationToken);
        var groups = await (
            from membership in database.ScimGroupUserMembers.AsNoTracking()
            join scimGroup in database.ScimGroups.AsNoTracking()
                on membership.GroupId equals scimGroup.Id
            where membership.UserId == user.Id
            orderby scimGroup.DisplayName, scimGroup.Id
            select new ScimMember
            {
                Value = scimGroup.Id,
                Type = "direct",
                Display = scimGroup.DisplayName
            })
            .ToArrayAsync(cancellationToken);
        var created = profile?.CreatedAtUtc
            ?? NormalizeUtc(user.Timestamp);
        var updated = profile?.UpdatedAtUtc
            ?? NormalizeUtc(user.Timestamp);
        var active = user.LockoutEnd is not { } end
            || end <= DateTimeOffset.UtcNow;

        return new ScimUserResource
        {
            Id = user.Id,
            ExternalId = profile?.ExternalId,
            UserName = user.UserName ?? string.Empty,
            Name = profile is null
                ? null
                : new ScimName
                {
                    Formatted = profile.FormattedName,
                    FamilyName = profile.FamilyName,
                    GivenName = profile.GivenName,
                    MiddleName = profile.MiddleName,
                    HonorificPrefix = profile.HonorificPrefix,
                    HonorificSuffix = profile.HonorificSuffix
                },
            DisplayName = profile?.DisplayName,
            Title = profile?.Title,
            UserType = profile?.UserType,
            PreferredLanguage = profile?.PreferredLanguage,
            Locale = profile?.Locale,
            Timezone = profile?.Timezone,
            Active = active,
            Emails = string.IsNullOrWhiteSpace(user.Email)
                ? []
                :
                [
                    new ScimEmail
                    {
                        Value = user.Email,
                        Type = "work",
                        Primary = true
                    }
                ],
            Groups = groups,
            Meta = new ScimMeta
            {
                ResourceType = "User",
                Created = created,
                LastModified = updated
            }
        };
    }

    private async Task<ScimGroupResource> GetGroupWithoutAuditAsync(
        string id,
        CancellationToken cancellationToken)
    {
        var group = await database.ScimGroups
            .AsNoTracking()
            .SingleOrDefaultAsync(group => group.Id == id, cancellationToken)
            ?? throw ScimException.NotFound(
                $"SCIM group '{id}' was not found.");
        return await BuildGroupAsync(group, cancellationToken);
    }

    private async Task<ScimGroupResource> BuildGroupAsync(
        ScimGroup scimGroup,
        CancellationToken cancellationToken)
    {
        var users = await (
            from membership in database.ScimGroupUserMembers.AsNoTracking()
            join user in database.Users.AsNoTracking()
                on membership.UserId equals user.Id
            where membership.GroupId == scimGroup.Id
            orderby user.UserName, user.Id
            select new ScimMember
            {
                Value = user.Id,
                Type = "User",
                Display = user.UserName
            })
            .ToArrayAsync(cancellationToken);
        var groups = await (
            from membership in database.ScimGroupGroupMembers.AsNoTracking()
            join member in database.ScimGroups.AsNoTracking()
                on membership.MemberGroupId equals member.Id
            where membership.GroupId == scimGroup.Id
            orderby member.DisplayName, member.Id
            select new ScimMember
            {
                Value = member.Id,
                Type = "Group",
                Display = member.DisplayName
            })
            .ToArrayAsync(cancellationToken);

        return new ScimGroupResource
        {
            Id = scimGroup.Id,
            ExternalId = scimGroup.ExternalId,
            DisplayName = scimGroup.DisplayName,
            Members = users.Concat(groups).ToArray(),
            Meta = new ScimMeta
            {
                ResourceType = "Group",
                Created = scimGroup.CreatedAtUtc,
                LastModified = scimGroup.UpdatedAtUtc
            }
        };
    }

    private async Task ReplaceGroupMembersAsync(
        string groupId,
        IReadOnlyList<ScimMember>? members,
        CancellationToken cancellationToken)
    {
        await database.ScimGroupUserMembers
            .Where(member => member.GroupId == groupId)
            .ExecuteDeleteAsync(cancellationToken);
        await database.ScimGroupGroupMembers
            .Where(member => member.GroupId == groupId)
            .ExecuteDeleteAsync(cancellationToken);

        var normalized = (members ?? [])
            .Where(member => !string.IsNullOrWhiteSpace(member.Value))
            .GroupBy(
                member => (
                    Value: member.Value.Trim(),
                    Type: member.Type?.Trim()),
                StringTupleComparer.Instance)
            .Select(group => group.First())
            .ToArray();
        foreach (var member in normalized)
        {
            var memberId = member.Value.Trim();
            var type = await ResolveMemberTypeAsync(
                memberId,
                member.Type,
                cancellationToken);
            if (type == "User")
            {
                database.ScimGroupUserMembers.Add(
                    new ScimGroupUserMember
                    {
                        GroupId = groupId,
                        UserId = memberId
                    });
                continue;
            }

            if (string.Equals(groupId, memberId, StringComparison.Ordinal))
            {
                throw ScimException.BadRequest(
                    "A SCIM group cannot contain itself.",
                    "invalidValue");
            }
            if (await WouldCreateGroupCycleAsync(
                groupId,
                memberId,
                cancellationToken))
            {
                throw ScimException.BadRequest(
                    "The requested nested group membership would create a cycle.",
                    "invalidValue");
            }

            database.ScimGroupGroupMembers.Add(
                new ScimGroupGroupMember
                {
                    GroupId = groupId,
                    MemberGroupId = memberId
                });
        }
    }

    private async Task<string> ResolveMemberTypeAsync(
        string memberId,
        string? requestedType,
        CancellationToken cancellationToken)
    {
        if (string.Equals(
            requestedType,
            "User",
            StringComparison.OrdinalIgnoreCase))
        {
            if (!await database.Users.AnyAsync(
                user => user.Id == memberId,
                cancellationToken))
            {
                throw ScimException.BadRequest(
                    $"SCIM user member '{memberId}' was not found.",
                    "invalidValue");
            }
            return "User";
        }

        if (string.Equals(
            requestedType,
            "Group",
            StringComparison.OrdinalIgnoreCase))
        {
            if (!await database.ScimGroups.AnyAsync(
                group => group.Id == memberId,
                cancellationToken))
            {
                throw ScimException.BadRequest(
                    $"SCIM group member '{memberId}' was not found.",
                    "invalidValue");
            }
            return "Group";
        }

        if (!string.IsNullOrWhiteSpace(requestedType))
        {
            throw ScimException.BadRequest(
                $"SCIM member type '{requestedType}' is not supported.",
                "invalidValue");
        }

        if (await database.Users.AnyAsync(
            user => user.Id == memberId,
            cancellationToken))
        {
            return "User";
        }
        if (await database.ScimGroups.AnyAsync(
            group => group.Id == memberId,
            cancellationToken))
        {
            return "Group";
        }

        throw ScimException.BadRequest(
            $"SCIM member '{memberId}' was not found.",
            "invalidValue");
    }

    private async Task<bool> WouldCreateGroupCycleAsync(
        string groupId,
        string memberGroupId,
        CancellationToken cancellationToken)
    {
        var links = await database.ScimGroupGroupMembers
            .AsNoTracking()
            .Select(member => new
            {
                member.GroupId,
                member.MemberGroupId
            })
            .ToArrayAsync(cancellationToken);
        var adjacency = links
            .GroupBy(link => link.GroupId, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => group
                    .Select(link => link.MemberGroupId)
                    .ToArray(),
                StringComparer.Ordinal);
        var pending = new Queue<string>();
        var visited = new HashSet<string>(StringComparer.Ordinal);
        pending.Enqueue(memberGroupId);
        while (pending.TryDequeue(out var current))
        {
            if (!visited.Add(current))
            {
                continue;
            }
            if (string.Equals(current, groupId, StringComparison.Ordinal))
            {
                return true;
            }
            if (!adjacency.TryGetValue(current, out var children))
            {
                continue;
            }
            foreach (var child in children)
            {
                pending.Enqueue(child);
            }
        }

        return false;
    }

    private static void ApplyUserPatch(
        ScimUserResource resource,
        ScimPatchOperation operation)
    {
        var op = NormalizePatchOperation(operation);
        if (string.IsNullOrWhiteSpace(operation.Path))
        {
            if (op == "remove")
            {
                throw ScimException.BadRequest(
                    "A remove operation requires a path.",
                    "noTarget");
            }
            ApplyUserObjectPatch(resource, operation.Value);
            return;
        }

        var path = operation.Path.Trim();
        var remove = op == "remove";
        if (path.Equals("userName", StringComparison.OrdinalIgnoreCase))
        {
            if (remove)
            {
                throw ScimException.BadRequest(
                    "The required userName attribute cannot be removed.",
                    "mutability");
            }
            resource.UserName = JsonString(operation.Value, path);
        }
        else if (path.Equals("active", StringComparison.OrdinalIgnoreCase))
        {
            resource.Active = remove || operation.Value.ValueKind is JsonValueKind.Null
                ? true
                : operation.Value.GetBoolean();
        }
        else if (path.Equals("externalId", StringComparison.OrdinalIgnoreCase))
        {
            resource.ExternalId = remove
                ? null
                : JsonNullableString(operation.Value, path);
        }
        else if (path.Equals("displayName", StringComparison.OrdinalIgnoreCase))
        {
            resource.DisplayName = remove
                ? null
                : JsonNullableString(operation.Value, path);
        }
        else if (path.Equals("title", StringComparison.OrdinalIgnoreCase))
        {
            resource.Title = remove
                ? null
                : JsonNullableString(operation.Value, path);
        }
        else if (path.Equals("userType", StringComparison.OrdinalIgnoreCase))
        {
            resource.UserType = remove
                ? null
                : JsonNullableString(operation.Value, path);
        }
        else if (path.Equals(
            "preferredLanguage",
            StringComparison.OrdinalIgnoreCase))
        {
            resource.PreferredLanguage = remove
                ? null
                : JsonNullableString(operation.Value, path);
        }
        else if (path.Equals("locale", StringComparison.OrdinalIgnoreCase))
        {
            resource.Locale = remove
                ? null
                : JsonNullableString(operation.Value, path);
        }
        else if (path.Equals("timezone", StringComparison.OrdinalIgnoreCase))
        {
            resource.Timezone = remove
                ? null
                : JsonNullableString(operation.Value, path);
        }
        else if (path.StartsWith("name.", StringComparison.OrdinalIgnoreCase))
        {
            resource.Name ??= new ScimName();
            SetNameValue(
                resource.Name,
                path[5..],
                remove ? null : JsonNullableString(operation.Value, path));
        }
        else if (path.Equals("emails", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("emails[", StringComparison.OrdinalIgnoreCase))
        {
            resource.Emails = remove
                ? []
                : JsonEmails(operation.Value);
        }
        else if (path.Equals("password", StringComparison.OrdinalIgnoreCase))
        {
            resource.Password = remove
                ? null
                : JsonString(operation.Value, path);
        }
        else
        {
            throw ScimException.BadRequest(
                $"SCIM user path '{path}' is not supported.",
                "invalidPath");
        }
    }

    private static void ApplyUserObjectPatch(
        ScimUserResource resource,
        JsonElement value)
    {
        if (value.ValueKind is not JsonValueKind.Object)
        {
            throw ScimException.BadRequest(
                "A pathless SCIM user patch requires an object value.",
                "invalidValue");
        }
        foreach (var property in value.EnumerateObject())
        {
            ApplyUserPatch(
                resource,
                new ScimPatchOperation
                {
                    Op = "replace",
                    Path = property.Name,
                    Value = property.Value.Clone()
                });
        }
    }

    private static void ApplyGroupPatch(
        ScimGroupResource resource,
        ScimPatchOperation operation)
    {
        var op = NormalizePatchOperation(operation);
        if (string.IsNullOrWhiteSpace(operation.Path))
        {
            if (op == "remove"
                || operation.Value.ValueKind is not JsonValueKind.Object)
            {
                throw ScimException.BadRequest(
                    "A pathless SCIM group patch requires an object value.",
                    "invalidValue");
            }
            foreach (var property in operation.Value.EnumerateObject())
            {
                ApplyGroupPatch(
                    resource,
                    new ScimPatchOperation
                    {
                        Op = op,
                        Path = property.Name,
                        Value = property.Value.Clone()
                    });
            }
            return;
        }

        var path = operation.Path.Trim();
        if (path.Equals("displayName", StringComparison.OrdinalIgnoreCase))
        {
            if (op == "remove")
            {
                throw ScimException.BadRequest(
                    "The required displayName attribute cannot be removed.",
                    "mutability");
            }
            resource.DisplayName = JsonString(operation.Value, path);
            return;
        }
        if (path.Equals("externalId", StringComparison.OrdinalIgnoreCase))
        {
            resource.ExternalId = op == "remove"
                ? null
                : JsonNullableString(operation.Value, path);
            return;
        }
        if (path.Equals("members", StringComparison.OrdinalIgnoreCase))
        {
            var incoming = operation.Value.ValueKind is JsonValueKind.Undefined
                or JsonValueKind.Null
                ? []
                : JsonMembers(operation.Value);
            resource.Members = op switch
            {
                "add" => resource.Members
                    .Concat(incoming)
                    .GroupBy(
                        member => (member.Value, member.Type),
                        StringTupleComparer.Instance)
                    .Select(group => group.First())
                    .ToArray(),
                "replace" => incoming,
                "remove" when incoming.Count > 0 =>
                    resource.Members
                        .Where(current => !incoming.Any(value =>
                            string.Equals(
                                value.Value,
                                current.Value,
                                StringComparison.Ordinal)))
                        .ToArray(),
                "remove" => [],
                _ => resource.Members
            };
            return;
        }

        var match = MemberPathFilterRegex().Match(path);
        if (match.Success && op == "remove")
        {
            var encoded = $"\"{match.Groups["value"].Value}\"";
            var memberId = JsonSerializer.Deserialize<string>(encoded)
                ?? string.Empty;
            resource.Members = resource.Members
                .Where(member => !string.Equals(
                    member.Value,
                    memberId,
                    StringComparison.Ordinal))
                .ToArray();
            return;
        }

        throw ScimException.BadRequest(
            $"SCIM group path '{path}' is not supported.",
            "invalidPath");
    }

    private static string NormalizePatchOperation(
        ScimPatchOperation operation)
    {
        var op = operation.Op?.Trim().ToLowerInvariant();
        if (op is not ("add" or "replace" or "remove"))
        {
            throw ScimException.BadRequest(
                $"SCIM patch operation '{operation.Op}' is not supported.",
                "invalidSyntax");
        }
        return op;
    }

    private static void ValidatePatchRequest(ScimPatchRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!request.Schemas.Contains(
            ScimSchemas.PatchOperation,
            StringComparer.Ordinal))
        {
            throw ScimException.BadRequest(
                $"The schemas collection must contain '{ScimSchemas.PatchOperation}'.",
                "invalidSyntax");
        }
        if (request.Operations.Count is 0)
        {
            throw ScimException.BadRequest(
                "At least one SCIM patch operation is required.",
                "invalidSyntax");
        }
    }

    private static void ValidateUserResource(ScimUserResource resource)
    {
        if (string.IsNullOrWhiteSpace(resource.UserName))
        {
            throw ScimException.BadRequest(
                "The SCIM userName attribute is required.",
                "invalidValue");
        }
        if (resource.UserName.Trim().Length > 256)
        {
            throw ScimException.BadRequest(
                "The SCIM userName attribute exceeds 256 characters.",
                "invalidValue");
        }
        if (resource.Emails?.Any(email =>
            string.IsNullOrWhiteSpace(email.Value)) is true)
        {
            throw ScimException.BadRequest(
                "SCIM email values cannot be empty.",
                "invalidValue");
        }
    }

    private static void ValidateGroupResource(ScimGroupResource resource)
    {
        if (string.IsNullOrWhiteSpace(resource.DisplayName))
        {
            throw ScimException.BadRequest(
                "The SCIM group displayName attribute is required.",
                "invalidValue");
        }
        if (resource.DisplayName.Trim().Length > 256)
        {
            throw ScimException.BadRequest(
                "The SCIM group displayName attribute exceeds 256 characters.",
                "invalidValue");
        }
    }

    private static string? PrimaryEmail(ScimUserResource resource)
    {
        var emails = resource.Emails?
            .Where(email => !string.IsNullOrWhiteSpace(email.Value))
            .ToArray() ?? [];
        return emails.FirstOrDefault(email => email.Primary)?.Value.Trim()
            ?? emails.FirstOrDefault()?.Value.Trim();
    }

    private static ScimUserProfile NewProfile(
        string userId,
        ScimUserResource resource,
        DateTime now)
    {
        var profile = new ScimUserProfile
        {
            UserId = userId,
            CreatedAtUtc = now,
            UpdatedAtUtc = now
        };
        ApplyProfile(profile, resource);
        return profile;
    }

    private static void ApplyProfile(
        ScimUserProfile profile,
        ScimUserResource resource)
    {
        profile.ExternalId = NormalizeOptional(resource.ExternalId);
        profile.DisplayName = NormalizeOptional(resource.DisplayName);
        profile.FormattedName = NormalizeOptional(resource.Name?.Formatted);
        profile.FamilyName = NormalizeOptional(resource.Name?.FamilyName);
        profile.GivenName = NormalizeOptional(resource.Name?.GivenName);
        profile.MiddleName = NormalizeOptional(resource.Name?.MiddleName);
        profile.HonorificPrefix =
            NormalizeOptional(resource.Name?.HonorificPrefix);
        profile.HonorificSuffix =
            NormalizeOptional(resource.Name?.HonorificSuffix);
        profile.Title = NormalizeOptional(resource.Title);
        profile.UserType = NormalizeOptional(resource.UserType);
        profile.PreferredLanguage =
            NormalizeOptional(resource.PreferredLanguage);
        profile.Locale = NormalizeOptional(resource.Locale);
        profile.Timezone = NormalizeOptional(resource.Timezone);
    }

    private static void EnsureIdentityResult(IdentityResult result)
    {
        if (result.Succeeded)
        {
            return;
        }

        var duplicate = result.Errors.Any(error =>
            error.Code is "DuplicateUserName" or "DuplicateEmail");
        if (duplicate)
        {
            throw ScimException.Conflict(
                "A SCIM user with the same userName or email already exists.");
        }
        throw ScimException.BadRequest(
            string.Join(
                ' ',
                result.Errors.Select(error => error.Description)),
            "invalidValue");
    }

    private (int StartIndex, int Skip, int Count) Paging(
        int startIndex,
        int count)
    {
        var normalizedStart = Math.Max(startIndex, 1);
        var max = Math.Clamp(options.Value.MaxResults, 1, 1000);
        var normalizedCount = Math.Clamp(count, 0, max);
        return (
            normalizedStart,
            normalizedStart - 1,
            normalizedCount);
    }

    private void AddAudit(
        ScimRequestContext context,
        string capability,
        string resourceType,
        string? resourceId,
        string operationOutcome,
        string reasonCode)
    {
        database.ManagementAuditEvents.Add(new ManagementAuditEvent
        {
            OccurredAtUtc = DateTime.UtcNow,
            OperatorSubject = Truncate(context.Actor, 255),
            Capability = Truncate(capability, 150),
            ResourceType = Truncate(resourceType, 100),
            ResourceId = TruncateOptional(resourceId, 255),
            AuthorizationOutcome = "allowed",
            OperationOutcome = Truncate(operationOutcome, 50),
            ReasonCode = TruncateOptional(reasonCode, 100),
            CorrelationId = Truncate(context.CorrelationId, 100),
            AuthenticationMethods = TruncateOptional(
                context.AuthenticationMethods,
                255)
        });
    }

    private async Task RollbackAsync(
        Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction)
    {
        await transaction.RollbackAsync(CancellationToken.None);
        database.ChangeTracker.Clear();
    }

    private static string JsonString(JsonElement value, string path)
    {
        var result = JsonNullableString(value, path);
        if (string.IsNullOrWhiteSpace(result))
        {
            throw ScimException.BadRequest(
                $"SCIM attribute '{path}' requires a string value.",
                "invalidValue");
        }
        return result;
    }

    private static string? JsonNullableString(
        JsonElement value,
        string path)
    {
        if (value.ValueKind is JsonValueKind.Null)
        {
            return null;
        }
        if (value.ValueKind is not JsonValueKind.String)
        {
            throw ScimException.BadRequest(
                $"SCIM attribute '{path}' requires a string value.",
                "invalidValue");
        }
        return NormalizeOptional(value.GetString());
    }

    private static IReadOnlyList<ScimEmail> JsonEmails(JsonElement value)
    {
        try
        {
            if (value.ValueKind is JsonValueKind.Array)
            {
                return JsonSerializer.Deserialize<ScimEmail[]>(
                    value.GetRawText(),
                    PatchJsonOptions) ?? [];
            }
            var email = JsonSerializer.Deserialize<ScimEmail>(
                value.GetRawText(),
                PatchJsonOptions);
            return email is null ? [] : [email];
        }
        catch (JsonException)
        {
            throw ScimException.BadRequest(
                "The SCIM emails value is invalid.",
                "invalidValue");
        }
    }

    private static IReadOnlyList<ScimMember> JsonMembers(JsonElement value)
    {
        try
        {
            if (value.ValueKind is JsonValueKind.Array)
            {
                return JsonSerializer.Deserialize<ScimMember[]>(
                    value.GetRawText(),
                    PatchJsonOptions) ?? [];
            }
            var member = JsonSerializer.Deserialize<ScimMember>(
                value.GetRawText(),
                PatchJsonOptions);
            return member is null ? [] : [member];
        }
        catch (JsonException)
        {
            throw ScimException.BadRequest(
                "The SCIM members value is invalid.",
                "invalidValue");
        }
    }

    private static void SetNameValue(
        ScimName name,
        string attribute,
        string? value)
    {
        switch (attribute.ToLowerInvariant())
        {
            case "formatted":
                name.Formatted = value;
                break;
            case "familyname":
                name.FamilyName = value;
                break;
            case "givenname":
                name.GivenName = value;
                break;
            case "middlename":
                name.MiddleName = value;
                break;
            case "honorificprefix":
                name.HonorificPrefix = value;
                break;
            case "honorificsuffix":
                name.HonorificSuffix = value;
                break;
            default:
                throw ScimException.BadRequest(
                    $"SCIM name attribute '{attribute}' is not supported.",
                    "invalidPath");
        }
    }

    private static string? NormalizeOptional(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static DateTime NormalizeUtc(DateTime value) =>
        value.Kind switch
        {
            DateTimeKind.Utc => value,
            DateTimeKind.Local => value.ToUniversalTime(),
            _ => DateTime.SpecifyKind(value, DateTimeKind.Utc)
        };

    private static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..maxLength];

    private static string? TruncateOptional(
        string? value,
        int maxLength) =>
        value is null || value.Length <= maxLength
            ? value
            : value[..maxLength];

    private sealed class StringTupleComparer
        : IEqualityComparer<(string Value, string? Type)>
    {
        public static StringTupleComparer Instance { get; } = new();

        public bool Equals(
            (string Value, string? Type) x,
            (string Value, string? Type) y) =>
            string.Equals(x.Value, y.Value, StringComparison.Ordinal)
            && string.Equals(
                x.Type,
                y.Type,
                StringComparison.OrdinalIgnoreCase);

        public int GetHashCode((string Value, string? Type) value) =>
            HashCode.Combine(
                StringComparer.Ordinal.GetHashCode(value.Value),
                value.Type is null
                    ? 0
                    : StringComparer.OrdinalIgnoreCase.GetHashCode(value.Type));
    }
}
