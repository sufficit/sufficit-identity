using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Scim;

internal sealed partial class ScimProvisioningService
{
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

        EnqueueReadAudit(
            context,
            "scim.groups.read",
            "scim-group-collection",
            null,
            "succeeded",
            "scim_groups_listed");

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
        EnqueueReadAudit(
            context,
            "scim.groups.read",
            "scim-group",
            id,
            "succeeded",
            "scim_group_read");
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
}
