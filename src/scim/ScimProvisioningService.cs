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
    ISecurityEventTrigger securityEvents,
    IOptions<ScimOptions> options,
    ILogger<ScimProvisioningService> logger,
    IScimAuditQueue? auditQueue = null) : IScimProvisioningService
{
    private static readonly JsonSerializerOptions PatchJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    [GeneratedRegex(
        "^(?<attribute>id|userName|externalId|displayName)\\s+eq\\s+\"(?<value>(?:\\\\.|[^\"\\\\])*)\"$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 250)]
    private static partial Regex EqualityFilterRegex();

    [GeneratedRegex(
        "^members\\s*\\[\\s*value\\s+eq\\s+\"(?<value>(?:\\\\.|[^\"\\\\])*)\"\\s*\\]$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 250)]
    private static partial Regex MemberPathFilterRegex();

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
