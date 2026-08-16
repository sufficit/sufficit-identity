using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Mcp;

/// <summary>
/// Self-service tools: every operation is bound to the authenticated subject
/// and never touches another account. Password, e-mail and MFA changes are
/// deliberately excluded — those flows require step-up verification in the
/// browser, not an agent surface.
/// </summary>
public sealed class SelfServiceMcpTools(
    UserManager<ApplicationUser> users,
    IOpenIddictTokenManager tokens,
    IOpenIddictAuthorizationManager authorizations,
    IOpenIddictApplicationManager applications,
    AppDbContext database)
{
    private const int MaxListed = 100;

    public IReadOnlyList<McpToolDescriptor> Tools =>
    [
        new(
            "me_get",
            "Returns your own profile (id, username, e-mail, phone, display name, MFA status).",
            EmptySchema,
            GetAsync),
        new(
            "me_update",
            "Updates safe fields of your own profile: displayName and/or phoneNumber. Password, e-mail and MFA cannot be changed here.",
            new
            {
                type = "object",
                properties = new Dictionary<string, object>
                {
                    ["displayName"] = new { type = "string", description = "New display name." },
                    ["phoneNumber"] = new { type = "string", description = "New phone number (E.164 preferred)." },
                },
                required = Array.Empty<string>(),
            },
            UpdateAsync),
        new(
            "me_sessions_list",
            "Lists credentials/sessions issued to you (tokens), with client, status and validity.",
            EmptySchema,
            SessionsListAsync),
        new(
            "me_session_revoke",
            "Revokes one of YOUR issued credentials/sessions by id.",
            new
            {
                type = "object",
                properties = new Dictionary<string, object>
                {
                    ["id"] = new { type = "string", description = "Session id from me_sessions_list." },
                },
                required = new[] { "id" },
            },
            SessionRevokeAsync),
        new(
            "me_authorizations_list",
            "Lists applications you granted access to (consents), with scopes.",
            EmptySchema,
            AuthorizationsListAsync),
        new(
            "me_authorization_revoke",
            "Revokes one of YOUR application grants by id.",
            new
            {
                type = "object",
                properties = new Dictionary<string, object>
                {
                    ["id"] = new { type = "string", description = "Authorization id from me_authorizations_list." },
                },
                required = new[] { "id" },
            },
            AuthorizationRevokeAsync),
    ];

    private static readonly object EmptySchema = new
    {
        type = "object",
        properties = new Dictionary<string, object>(),
        required = Array.Empty<string>(),
    };

    private async Task<object> GetAsync(
        McpToolCallContext context, JsonElement args, CancellationToken ct)
    {
        var user = await RequireUserAsync(context);
        var claims = await users.GetClaimsAsync(user);
        return new
        {
            id = user.Id,
            userName = user.UserName,
            email = user.Email,
            emailConfirmed = user.EmailConfirmed,
            phoneNumber = user.PhoneNumber,
            phoneNumberConfirmed = user.PhoneNumberConfirmed,
            displayName = claims.FirstOrDefault(claim =>
                claim.Type is "name" or ClaimTypes.Name)?.Value,
            twoFactorEnabled = user.TwoFactorEnabled,
            createdAtUtc = user.CreatedAtUtc,
        };
    }

    private async Task<object> UpdateAsync(
        McpToolCallContext context, JsonElement args, CancellationToken ct)
    {
        var user = await RequireUserAsync(context);
        var displayName = IdentityMcpToolRegistry.ReadString(args, "displayName");
        var phoneNumber = IdentityMcpToolRegistry.ReadString(args, "phoneNumber");
        if (displayName is null && phoneNumber is null)
            throw new McpToolException(
                "Provide displayName and/or phoneNumber.");

        if (phoneNumber is not null)
        {
            var result = await users.SetPhoneNumberAsync(user, phoneNumber);
            if (!result.Succeeded)
                throw new McpToolException(Describe(result));
        }

        if (displayName is not null)
        {
            var claims = await users.GetClaimsAsync(user);
            var existing = claims.FirstOrDefault(claim =>
                claim.Type is "name" or ClaimTypes.Name);
            var replacement = new Claim(existing?.Type ?? "name", displayName);
            var result = existing is null
                ? await users.AddClaimAsync(user, replacement)
                : await users.ReplaceClaimAsync(user, existing, replacement);
            if (!result.Succeeded)
                throw new McpToolException(Describe(result));
        }

        return new { updated = true };
    }

    private async Task<object> SessionsListAsync(
        McpToolCallContext context, JsonElement args, CancellationToken ct)
    {
        var items = new List<object>();
        await foreach (var token in tokens.FindBySubjectAsync(context.Subject, ct))
        {
            if (items.Count >= MaxListed) break;
            items.Add(new
            {
                id = await tokens.GetIdAsync(token, ct),
                type = await tokens.GetTypeAsync(token, ct),
                status = await tokens.GetStatusAsync(token, ct),
                client = await ClientIdOfAsync(
                    await tokens.GetApplicationIdAsync(token, ct), ct),
                createdAtUtc = await tokens.GetCreationDateAsync(token, ct),
                expiresAtUtc = await tokens.GetExpirationDateAsync(token, ct),
            });
        }
        return new { sessions = items, truncated = items.Count >= MaxListed };
    }

    private async Task<object> SessionRevokeAsync(
        McpToolCallContext context, JsonElement args, CancellationToken ct)
    {
        var id = IdentityMcpToolRegistry.RequireString(args, "id");
        var token = await tokens.FindByIdAsync(id, ct)
            ?? throw new McpToolException("Session not found.");
        if (!string.Equals(
                await tokens.GetSubjectAsync(token, ct),
                context.Subject,
                StringComparison.Ordinal))
            throw new McpToolException("Session not found.");
        if (!await tokens.TryRevokeAsync(token, ct))
            throw new McpToolException("Session could not be revoked.");
        await AuditAsync(
            context,
            ManagementCapabilities.SessionsRevoke,
            new ManagementResource(ManagementResourceTypes.Session, id),
            "session_revoked",
            ct);
        return new { revoked = true, id };
    }

    private async Task<object> AuthorizationsListAsync(
        McpToolCallContext context, JsonElement args, CancellationToken ct)
    {
        var items = new List<object>();
        await foreach (var grant in authorizations.FindBySubjectAsync(
            context.Subject, ct))
        {
            if (items.Count >= MaxListed) break;
            items.Add(new
            {
                id = await authorizations.GetIdAsync(grant, ct),
                type = await authorizations.GetTypeAsync(grant, ct),
                status = await authorizations.GetStatusAsync(grant, ct),
                client = await ClientIdOfAsync(
                    await authorizations.GetApplicationIdAsync(grant, ct), ct),
                scopes = (await authorizations.GetScopesAsync(grant, ct)).ToArray(),
                createdAtUtc = await authorizations.GetCreationDateAsync(grant, ct),
            });
        }
        return new { authorizations = items, truncated = items.Count >= MaxListed };
    }

    private async Task<object> AuthorizationRevokeAsync(
        McpToolCallContext context, JsonElement args, CancellationToken ct)
    {
        var id = IdentityMcpToolRegistry.RequireString(args, "id");
        var grant = await authorizations.FindByIdAsync(id, ct)
            ?? throw new McpToolException("Authorization not found.");
        if (!string.Equals(
                await authorizations.GetSubjectAsync(grant, ct),
                context.Subject,
                StringComparison.Ordinal))
            throw new McpToolException("Authorization not found.");
        if (!await authorizations.TryRevokeAsync(grant, ct))
            throw new McpToolException("Authorization could not be revoked.");
        await AuditAsync(
            context,
            ManagementCapabilities.AuthorizationsRevoke,
            new ManagementResource(ManagementResourceTypes.Authorization, id),
            "authorization_revoked",
            ct);
        return new { revoked = true, id };
    }

    private async Task<ApplicationUser> RequireUserAsync(McpToolCallContext context) =>
        await users.FindByIdAsync(context.Subject)
        ?? throw new McpToolException("Authenticated user no longer exists.");

    private async Task<string?> ClientIdOfAsync(string? applicationId, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(applicationId)) return null;
        var application = await applications.FindByIdAsync(applicationId, ct);
        return application is null
            ? null
            : await applications.GetClientIdAsync(application, ct);
    }

    private async Task AuditAsync(
        McpToolCallContext context,
        string capability,
        ManagementResource resource,
        string reason,
        CancellationToken ct)
    {
        database.ManagementAuditEvents.Add(
            Audit.ManagementAuditEventFactory.Create(
                context.AsManagementContext(),
                capability,
                resource,
                ManagementAuthorizationDecision.Allowed("mcp_self_service"),
                "succeeded",
                reason));
        await database.SaveChangesAsync(ct);
    }

    private static string Describe(IdentityResult result) =>
        string.Join("; ", result.Errors.Select(error => error.Description));
}
