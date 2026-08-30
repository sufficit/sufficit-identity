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

        EnqueueReadAudit(
            context,
            "scim.users.read",
            "scim-user-collection",
            null,
            "succeeded",
            "scim_users_listed");

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

        EnqueueReadAudit(
            context,
            "scim.users.read",
            "scim-user",
            id,
            "succeeded",
            "scim_user_read");
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
        var passwordChanged = false;
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
                passwordChanged = true;
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

        // CAEP credential-change: SCIM replacement has no target session, so
        // the emitted SET carries an iss_sub subject only. Only fires when a
        // new password was actually supplied in the replace payload.
        if (passwordChanged)
        {
            await securityEvents.CredentialChangedAsync(
                id,
                null,
                new CaepCredentialChange(
                    CaepCredentialType.Password,
                    CaepChangeOperation.Updated),
                cancellationToken);
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
}
