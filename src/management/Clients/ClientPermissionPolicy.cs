using OpenIddict.Abstractions;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Clients;

/// <summary>
/// Translation between the grants, scopes and consent type an operator edits
/// and the OpenIddict permission strings actually stored on a client.
/// </summary>
/// <remarks>
/// Extracted from <c>ClientManagementService</c>. This is the OAuth
/// authorization model of a client expressed as string permissions: which
/// grants it may use, which scopes it may request, and which protocol
/// endpoints follow from those grants. Getting it wrong either locks a client
/// out or silently widens what it can do, so it deserves to be read as one
/// unit. Behavior is unchanged — reason codes and messages are part of the API
/// contract and are reproduced exactly.
/// </remarks>
internal static class ClientPermissionPolicy
{
    /// <summary>
    /// Accepts either the bare grant name (<c>authorization_code</c>) or the
    /// already-prefixed OpenIddict permission, and always returns the
    /// prefixed form. Anything not listed is rejected rather than passed
    /// through, so an unrecognized grant cannot reach a client's permission
    /// set by way of a typo.
    /// </summary>
    internal static IReadOnlyList<string> NormalizeGrantTypes(
        IReadOnlyList<string>? values) =>
        (values ?? [])
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Select(value => value switch
            {
                "authorization_code" =>
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode =>
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                "client_credentials" =>
                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials =>
                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                "refresh_token" =>
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken =>
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                "device_code" =>
                    OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
                OpenIddictConstants.GrantTypes.DeviceCode =>
                    OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
                OpenIddictConstants.Permissions.GrantTypes.DeviceCode =>
                    OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
                OpenIddictConstants.GrantTypes.TokenExchange =>
                    OpenIddictConstants.Permissions.GrantTypes.TokenExchange,
                OpenIddictConstants.Permissions.GrantTypes.TokenExchange =>
                    OpenIddictConstants.Permissions.GrantTypes.TokenExchange,
                "password" =>
                    OpenIddictConstants.Permissions.GrantTypes.Password,
                OpenIddictConstants.Permissions.GrantTypes.Password =>
                    OpenIddictConstants.Permissions.GrantTypes.Password,
                "implicit" =>
                    OpenIddictConstants.Permissions.GrantTypes.Implicit,
                OpenIddictConstants.Permissions.GrantTypes.Implicit =>
                    OpenIddictConstants.Permissions.GrantTypes.Implicit,
                _ => throw new ManagementValidationException(
                    "unsupported_grant_type",
                    $"Grant type '{value}' is not supported by the Management API.",
                    "grantTypes")
            })
            .Distinct(StringComparer.Ordinal)
            .ToArray();

    internal static IReadOnlyList<string> NormalizeScopes(
        IReadOnlyList<string>? values) =>
        (values ?? [])
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Select(value => value.StartsWith(
                    OpenIddictConstants.Permissions.Prefixes.Scope,
                    StringComparison.Ordinal)
                ? value
                : OpenIddictConstants.Permissions.Prefixes.Scope + value)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

    /// <summary>
    /// Grants imply endpoint and response-type permissions; OpenIddict
    /// enforces those separately, so a client granted authorization_code
    /// without the authorization endpoint permission would simply fail at
    /// runtime. Deriving them here keeps the editable surface to the grants
    /// themselves.
    /// </summary>
    internal static void AddDerivedProtocolPermissions(
        OpenIddictApplicationDescriptor descriptor,
        IReadOnlyCollection<string> grantTypes)
    {
        if (grantTypes.Contains(
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                StringComparer.Ordinal)
            || grantTypes.Contains(
                OpenIddictConstants.Permissions.GrantTypes.Implicit,
                StringComparer.Ordinal))
        {
            descriptor.Permissions.Add(
                OpenIddictConstants.Permissions.Endpoints.Authorization);
        }

        if (grantTypes.Contains(
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                StringComparer.Ordinal)
            || grantTypes.Contains(
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                StringComparer.Ordinal)
            || grantTypes.Contains(
                OpenIddictConstants.Permissions.GrantTypes.Password,
                StringComparer.Ordinal)
            || grantTypes.Contains(
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                StringComparer.Ordinal)
            || grantTypes.Contains(
                OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
                StringComparer.Ordinal))
        {
            descriptor.Permissions.Add(
                OpenIddictConstants.Permissions.Endpoints.Token);
        }

        if (grantTypes.Contains(
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                StringComparer.Ordinal))
        {
            descriptor.Permissions.Add(
                OpenIddictConstants.Permissions.ResponseTypes.Code);
        }

        if (grantTypes.Contains(
                OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
                StringComparer.Ordinal))
        {
            descriptor.Permissions.Add(
                OpenIddictConstants.Permissions.Endpoints.DeviceAuthorization);
        }
    }

    /// <summary>
    /// Clears only the permissions this editor owns, ahead of rewriting them
    /// from the submitted grants and scopes.
    /// </summary>
    internal static void RemoveManagedPermissions(
        OpenIddictApplicationDescriptor descriptor)
    {
        // Keep protocol capabilities that this editor does not model (for
        // example introspection or custom endpoints). Only remove values that
        // are derived from the editable grants/scopes, otherwise a routine
        // display-name/redirect edit could silently weaken or broaden a client.
        var managed = descriptor.Permissions
            .Where(permission =>
                permission.StartsWith(
                    "gt:",
                    StringComparison.Ordinal)
                || permission.StartsWith(
                    OpenIddictConstants.Permissions.Prefixes.Scope,
                    StringComparison.Ordinal)
                || permission == OpenIddictConstants.Permissions.Endpoints.Authorization
                || permission == OpenIddictConstants.Permissions.Endpoints.Token
                || permission == OpenIddictConstants.Permissions.Endpoints.DeviceAuthorization
                || permission == OpenIddictConstants.Permissions.Endpoints.PushedAuthorization
                || permission == OpenIddictConstants.Permissions.ResponseTypes.Code)
            .ToArray();

        foreach (var permission in managed)
        {
            descriptor.Permissions.Remove(permission);
        }
    }

    internal static string? NormalizeConsentType(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        return raw switch
        {
            var value when string.Equals(
                    value,
                    "explicit",
                    StringComparison.OrdinalIgnoreCase)
                || string.Equals(
                    value,
                    OpenIddictConstants.ConsentTypes.Explicit,
                    StringComparison.OrdinalIgnoreCase)
                => OpenIddictConstants.ConsentTypes.Explicit,
            var value when string.Equals(
                    value,
                    "implicit",
                    StringComparison.OrdinalIgnoreCase)
                || string.Equals(
                    value,
                    OpenIddictConstants.ConsentTypes.Implicit,
                    StringComparison.OrdinalIgnoreCase)
                => OpenIddictConstants.ConsentTypes.Implicit,
            var value when string.Equals(
                    value,
                    "external",
                    StringComparison.OrdinalIgnoreCase)
                || string.Equals(
                    value,
                    OpenIddictConstants.ConsentTypes.External,
                    StringComparison.OrdinalIgnoreCase)
                => OpenIddictConstants.ConsentTypes.External,
            var value when string.Equals(
                    value,
                    "systematic",
                    StringComparison.OrdinalIgnoreCase)
                || string.Equals(
                    value,
                    OpenIddictConstants.ConsentTypes.Systematic,
                    StringComparison.OrdinalIgnoreCase)
                => OpenIddictConstants.ConsentTypes.Systematic,
            _ => throw new ManagementValidationException(
                "consent_type_invalid",
                $"Unknown consent type: '{raw}'. Valid values: explicit, " +
                "implicit, external, systematic.",
                "consentType")
        };
    }
}
