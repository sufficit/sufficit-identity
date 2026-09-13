using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.ServiceAccounts;

/// <summary>
/// Manages service-account roles.
///
/// Reading requires <c>identity.clients.read</c> and writing requires
/// <c>identity.clients.update</c> — the same capabilities that already govern
/// client registration, because that is exactly what this screen edits. A
/// machine role grants MANAGEMENT capabilities, so giving it its own weaker
/// capability would create an escalation shortcut: whoever could "only touch
/// service accounts" could hand an account the administrator role and log in
/// through it.
/// </summary>
public sealed class ServiceAccountManagementService(
    IOpenIddictApplicationManager applications,
    ManagementOperationGuard guard,
    IOptions<ManagementOptions> options) : IServiceAccountManagementService
{
    public async Task<ServiceAccountWorkspace> GetWorkspaceAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsRead,
            new ManagementResource(ManagementResourceTypes.ClientCollection),
            cancellationToken,
            auditDenial: true);

        var authorization = options.Value.Authorization;
        var accounts = new List<ServiceAccountSummary>();

        await foreach (var application in applications.ListAsync(
            cancellationToken: cancellationToken))
        {
            var permissions = await applications.GetPermissionsAsync(
                application, cancellationToken);
            var canRequestTokens = permissions.Contains(
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);

            var properties = await applications.GetPropertiesAsync(
                application, cancellationToken);
            var roles = properties.TryGetValue(
                authorization.ClientRolesPropertyName, out var declared)
                ? ParseRoles(declared)
                : [];

            // The list shows whoever CAN act as a system (has the grant) or
            // who ALREADY has a declared role — the second case catches the
            // forgotten configuration: a client that lost the grant but kept
            // the role is exactly the residue nobody finds without a screen.
            if (!canRequestTokens && roles.Count == 0)
            {
                continue;
            }

            accounts.Add(new ServiceAccountSummary(
                ClientId: (string)(await applications.GetClientIdAsync(
                    application, cancellationToken))!,
                DisplayName: (string?)await applications.GetDisplayNameAsync(
                    application, cancellationToken),
                CanRequestTokens: canRequestTokens,
                Roles: roles,
                Capabilities: Resolve(roles, authorization)));
        }

        return new ServiceAccountWorkspace(
            accounts
                .OrderBy(a => a.ClientId, StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            KnownRoles(authorization));
    }

    public async Task<ServiceAccountSummary> SetRolesAsync(
        string clientId,
        SetServiceAccountRolesCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsUpdate,
            new ManagementResource(ManagementResourceTypes.Client, clientId),
            cancellationToken,
            auditDenial: true);

        var application = await applications.FindByClientIdAsync(clientId, cancellationToken)
            ?? throw new ManagementValidationException(
                "client_not_found", $"Client '{clientId}' does not exist.");

        var authorization = options.Value.Authorization;
        var known = KnownRoles(authorization).Select(option => option.Role)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var roles = (command.Roles ?? [])
            .Where(role => !string.IsNullOrWhiteSpace(role))
            .Select(role => role.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        // An unknown role is refused on WRITE, unlike on read (where the
        // resolver silently ignores it so it doesn't break what is valid).
        // Whoever types "administrador" meaning "administrator" needs to hear
        // that now, not discover it in a 403 from the service weeks later.
        var unknown = roles.Where(role => !known.Contains(role)).ToArray();
        if (unknown.Length > 0)
        {
            throw new ManagementValidationException(
                "unknown_role",
                $"Unknown role in this deployment: {string.Join(", ", unknown)}. "
                + "Valid roles come from RoleCapabilities and FullAdministratorRoles.",
                field: "roles");
        }

        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application, cancellationToken);

        if (roles.Length == 0)
        {
            descriptor.Properties.Remove(authorization.ClientRolesPropertyName);
        }
        else
        {
            using var document = JsonDocument.Parse(JsonSerializer.Serialize(roles));
            descriptor.Properties[authorization.ClientRolesPropertyName] =
                document.RootElement.Clone();
        }

        await applications.UpdateAsync(application, descriptor, cancellationToken);

        var permissions = await applications.GetPermissionsAsync(application, cancellationToken);
        return new ServiceAccountSummary(
            ClientId: clientId,
            DisplayName: (string?)await applications.GetDisplayNameAsync(
                application, cancellationToken),
            CanRequestTokens: permissions.Contains(
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials),
            Roles: roles,
            Capabilities: Resolve(roles, authorization));
    }

    public async Task<ServiceAccountCreated> CreateAsync(
        CreateServiceAccountCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        // Creating requires ClientsCreate AND ClientsUpdate. Roles grant
        // management capabilities, so creating an account ALREADY WITH roles
        // is the same privilege grant as assigning them afterward —
        // requesting only the create capability would open the shortcut the
        // class comment describes, now through the creation door.
        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsCreate,
            new ManagementResource(ManagementResourceTypes.Client, command.ClientId),
            cancellationToken,
            auditDenial: true);
        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsUpdate,
            new ManagementResource(ManagementResourceTypes.Client, command.ClientId),
            cancellationToken,
            auditDenial: true);

        var clientId = (command.ClientId ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new ManagementValidationException(
                "client_id_required",
                "Provide the identifier of the service account.",
                field: "clientId");
        }

        if (await applications.FindByClientIdAsync(clientId, cancellationToken) is not null)
        {
            throw new ManagementValidationException(
                "client_already_exists",
                $"Client '{clientId}' already exists.",
                field: "clientId");
        }

        var authorization = options.Value.Authorization;
        var roles = NormalizeRoles(command.Roles, authorization);

        // Server-generated secret by default: 256 bits of CSPRNG. A machine
        // credential does not expire on its own, so its strength cannot
        // depend on what a human typed in a hurry.
        var secret = string.IsNullOrWhiteSpace(command.ClientSecret)
            ? Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32))
            : command.ClientSecret.Trim();

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = secret,
            DisplayName = string.IsNullOrWhiteSpace(command.DisplayName)
                ? clientId
                : command.DisplayName.Trim(),
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
        };

        // The shape is fixed on purpose: a service account talks to the token
        // endpoint via client_credentials and nothing else. No redirect, no
        // interactive flow — there is no user in this story.
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
        descriptor.Permissions.Add(
            OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
        // Service accounts managed by this surface need to be able to
        // request the administrative scope that protects the management
        // APIs. Assigning reserved scopes is deliberately blocked in the
        // common client CRUD; here it is part of the fixed, audited profile
        // of service-account creation.
        descriptor.Permissions.Add(
            OpenIddictConstants.Permissions.Prefixes.Scope
            + options.Value.RequiredScope);

        if (roles.Length > 0)
        {
            using var document = JsonDocument.Parse(JsonSerializer.Serialize(roles));
            descriptor.Properties[authorization.ClientRolesPropertyName] =
                document.RootElement.Clone();
        }

        await applications.CreateAsync(descriptor, cancellationToken);

        return new ServiceAccountCreated(
            new ServiceAccountSummary(
                ClientId: clientId,
                DisplayName: descriptor.DisplayName,
                CanRequestTokens: true,
                Roles: roles,
                Capabilities: Resolve(roles, authorization)),
            secret);
    }

    /// <summary>
    /// Distinct roles, no blanks, rejecting whatever this deployment does
    /// not recognize.
    /// </summary>
    private static string[] NormalizeRoles(
        IReadOnlyList<string>? requested,
        ManagementAuthorizationOptions authorization)
    {
        var roles = (requested ?? [])
            .Where(role => !string.IsNullOrWhiteSpace(role))
            .Select(role => role.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var known = KnownRoles(authorization).Select(option => option.Role)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var unknown = roles.Where(role => !known.Contains(role)).ToArray();
        if (unknown.Length > 0)
        {
            throw new ManagementValidationException(
                "unknown_role",
                $"Unknown role in this deployment: {string.Join(", ", unknown)}. "
                + "Valid roles come from RoleCapabilities and FullAdministratorRoles.",
                field: "roles");
        }

        return roles;
    }

    private static IReadOnlyList<ServiceAccountRoleOption> KnownRoles(
        ManagementAuthorizationOptions authorization)
    {
        var known = new List<ServiceAccountRoleOption>();

        foreach (var role in authorization.FullAdministratorRoles)
        {
            known.Add(new ServiceAccountRoleOption(
                role, [.. ManagementCapabilities.All.Order(StringComparer.Ordinal)], true));
        }

        foreach (var (role, mapped) in authorization.RoleCapabilities)
        {
            if (known.Any(option => string.Equals(
                    option.Role, role, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            known.Add(new ServiceAccountRoleOption(
                role, Resolve([role], authorization), false));
        }

        return known
            .OrderBy(option => option.Role, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    /// <summary>
    /// The SAME resolution as <c>ServicePrincipalEntitlementResolver</c>: a
    /// full-administrator role grants everything; the others grant whatever
    /// the map says; an unknown capability name is dropped. The screen must
    /// show exactly what the evaluator will grant, or it becomes a second
    /// opinion.
    /// </summary>
    private static IReadOnlyList<string> Resolve(
        IReadOnlyList<string> roles,
        ManagementAuthorizationOptions authorization)
    {
        var capabilities = new HashSet<string>(StringComparer.Ordinal);

        foreach (var role in roles)
        {
            if (authorization.FullAdministratorRoles.Contains(
                    role, StringComparer.OrdinalIgnoreCase))
            {
                capabilities.UnionWith(ManagementCapabilities.All);
                continue;
            }

            if (!authorization.RoleCapabilities.TryGetValue(role, out var mapped))
            {
                continue;
            }

            foreach (var raw in mapped ?? [])
            {
                var capability = ManagementCapabilities.Normalize(raw);
                if (ManagementCapabilities.All.Contains(capability))
                {
                    capabilities.Add(capability);
                }
            }
        }

        return capabilities.Order(StringComparer.Ordinal).ToArray();
    }

    private static IReadOnlyList<string> ParseRoles(JsonElement declared)
    {
        var roles = ImmutableArray.CreateBuilder<string>();

        switch (declared.ValueKind)
        {
            case JsonValueKind.Array:
                foreach (var item in declared.EnumerateArray())
                {
                    var value = item.ValueKind == JsonValueKind.String ? item.GetString() : null;
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        roles.Add(value.Trim());
                    }
                }
                break;

            case JsonValueKind.String:
                foreach (var value in (declared.GetString() ?? string.Empty)
                    .Split([' ', ','], StringSplitOptions.RemoveEmptyEntries))
                {
                    roles.Add(value.Trim());
                }
                break;
        }

        return roles.ToImmutable();
    }
}
