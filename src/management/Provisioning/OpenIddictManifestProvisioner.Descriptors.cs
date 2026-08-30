using System.Diagnostics;
using System.Text.Json;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Management.Provisioning;

public sealed partial class OpenIddictManifestProvisioner
{
    private static OpenIddictScopeDescriptor CreateScopeDescriptor(
        int schemaVersion,
        IdentityScopeManifest manifest,
        string manifestIdentity)
    {
        var descriptor = new OpenIddictScopeDescriptor
        {
            Name = manifest.Name,
            DisplayName = manifest.DisplayName,
            Description = manifest.Description,
        };

        descriptor.Resources.UnionWith(manifest.Resources);
        SetManifestProperties(
            descriptor.Properties,
            schemaVersion,
            secretReference: null,
            manifestIdentity);

        // The entitlement travels with the scope record so every replica reads
        // the same policy from the database, instead of each host repeating it
        // in configuration (eval 2026-08-30, F-2).
        var entitlements = ScopeEntitlements.Write(
            manifest.EntitlementClaims.Select(claim =>
                new ScopeEntitlementClaim(claim.Type, claim.Value)));
        if (entitlements is { } value)
        {
            descriptor.Properties[ScopeEntitlements.PropertyName] = value;
        }
        else
        {
            descriptor.Properties.Remove(ScopeEntitlements.PropertyName);
        }

        return descriptor;
    }

    private OpenIddictApplicationDescriptor CreateApplicationDescriptor(
        int schemaVersion,
        IdentityClientManifest manifest,
        string manifestIdentity)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = manifest.ClientId,
            ClientType = manifest.ClientType switch
            {
                ManifestClientTypes.Public => OpenIddictConstants.ClientTypes.Public,
                ManifestClientTypes.Confidential => OpenIddictConstants.ClientTypes.Confidential,
                _ => throw new UnreachableException(),
            },
            ConsentType = manifest.ConsentType switch
            {
                ManifestConsentTypes.Explicit => OpenIddictConstants.ConsentTypes.Explicit,
                ManifestConsentTypes.External => OpenIddictConstants.ConsentTypes.External,
                ManifestConsentTypes.Implicit => OpenIddictConstants.ConsentTypes.Implicit,
                ManifestConsentTypes.Systematic => OpenIddictConstants.ConsentTypes.Systematic,
                _ => throw new UnreachableException(),
            },
            DisplayName = manifest.DisplayName,
        };

        foreach (var grant in manifest.GrantTypes)
        {
            descriptor.Permissions.Add(grant switch
            {
                ManifestGrantTypes.AuthorizationCode =>
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                ManifestGrantTypes.ClientCredentials =>
                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                ManifestGrantTypes.DeviceCode =>
                    OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
                ManifestGrantTypes.RefreshToken =>
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                ManifestGrantTypes.TokenExchange =>
                    OpenIddictConstants.Permissions.GrantTypes.TokenExchange,
                _ => throw new UnreachableException(),
            });
        }

        if (manifest.GrantTypes.Contains(
                ManifestGrantTypes.AuthorizationCode,
                StringComparer.Ordinal))
        {
            descriptor.Permissions.Add(
                OpenIddictConstants.Permissions.Endpoints.Authorization);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
            descriptor.Permissions.Add(
                OpenIddictConstants.Permissions.Endpoints.EndSession);
        }

        if (manifest.GrantTypes.Contains(
                ManifestGrantTypes.ClientCredentials,
                StringComparer.Ordinal) ||
            manifest.GrantTypes.Contains(
                ManifestGrantTypes.RefreshToken,
                StringComparer.Ordinal) ||
            manifest.GrantTypes.Contains(
                ManifestGrantTypes.TokenExchange,
                StringComparer.Ordinal))
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
        }

        if (manifest.GrantTypes.Contains(
                ManifestGrantTypes.DeviceCode,
                StringComparer.Ordinal))
        {
            descriptor.Permissions.Add(
                OpenIddictConstants.Permissions.Endpoints.DeviceAuthorization);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
        }

        foreach (var responseType in manifest.ResponseTypes)
        {
            descriptor.Permissions.Add(responseType switch
            {
                ManifestResponseTypes.Code =>
                    OpenIddictConstants.Permissions.ResponseTypes.Code,
                _ => throw new UnreachableException(),
            });
        }

        foreach (var scope in manifest.Scopes)
        {
            descriptor.Permissions.Add(
                OpenIddictConstants.Permissions.Prefixes.Scope + scope);
        }

        descriptor.RedirectUris.UnionWith(manifest.RedirectUris);
        descriptor.PostLogoutRedirectUris.UnionWith(manifest.PostLogoutRedirectUris);
        SetNativeReturnUris(descriptor.Properties, manifest.NativeReturnUris);
        SetLogoutSettings(descriptor.Settings, manifest);

        if (_clientDefinitionValidator.RequiresProofKeyForCodeExchange(
                manifest.GrantTypes))
        {
            descriptor.Requirements.Add(
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
        }

        SetManifestProperties(
            descriptor.Properties,
            schemaVersion,
            manifest.SecretReference,
            manifestIdentity);

        return descriptor;
    }

    private static void ApplyManagedScopeValues(
        OpenIddictScopeDescriptor target,
        OpenIddictScopeDescriptor source)
    {
        target.Name = source.Name;
        target.DisplayName = source.DisplayName;
        target.Description = source.Description;
        target.Resources.Clear();
        target.Resources.UnionWith(source.Resources);
        CopyManifestProperties(target.Properties, source.Properties);
    }

    private static void ApplyManagedApplicationValues(
        OpenIddictApplicationDescriptor target,
        OpenIddictApplicationDescriptor source)
    {
        target.ClientId = source.ClientId;
        target.ClientType = source.ClientType;
        target.ConsentType = source.ConsentType;
        target.DisplayName = source.DisplayName;

        target.Permissions.Clear();
        target.Permissions.UnionWith(source.Permissions);
        target.RedirectUris.Clear();
        target.RedirectUris.UnionWith(source.RedirectUris);
        target.PostLogoutRedirectUris.Clear();
        target.PostLogoutRedirectUris.UnionWith(source.PostLogoutRedirectUris);
        target.Requirements.Clear();
        target.Requirements.UnionWith(source.Requirements);

        CopyManagedLogoutSettings(target.Settings, source.Settings);

        CopyManifestProperties(target.Properties, source.Properties);
    }

    private static bool ScopeEquals(
        OpenIddictScopeDescriptor current,
        OpenIddictScopeDescriptor desired) =>
        string.Equals(current.Name, desired.Name, StringComparison.Ordinal) &&
        string.Equals(current.DisplayName, desired.DisplayName, StringComparison.Ordinal) &&
        string.Equals(current.Description, desired.Description, StringComparison.Ordinal) &&
        current.Resources.SetEquals(desired.Resources) &&
        ManifestPropertiesEqual(current.Properties, desired.Properties);

    private static bool ApplicationEquals(
        OpenIddictApplicationDescriptor current,
        OpenIddictApplicationDescriptor desired) =>
        string.Equals(current.ClientId, desired.ClientId, StringComparison.Ordinal) &&
        string.Equals(current.ClientType, desired.ClientType, StringComparison.Ordinal) &&
        string.Equals(current.ConsentType, desired.ConsentType, StringComparison.Ordinal) &&
        string.Equals(current.DisplayName, desired.DisplayName, StringComparison.Ordinal) &&
        current.Permissions.SetEquals(desired.Permissions) &&
        current.RedirectUris.Select(uri => uri.OriginalString).ToHashSet(StringComparer.Ordinal)
            .SetEquals(desired.RedirectUris.Select(uri => uri.OriginalString)) &&
        current.PostLogoutRedirectUris.Select(uri => uri.OriginalString)
            .ToHashSet(StringComparer.Ordinal)
            .SetEquals(desired.PostLogoutRedirectUris.Select(uri => uri.OriginalString)) &&
        current.Requirements.SetEquals(desired.Requirements) &&
        ManagedLogoutSettingsEqual(current.Settings, desired.Settings) &&
        ManifestPropertiesEqual(current.Properties, desired.Properties);

    private static ClientDefinitionSnapshot Snapshot(
        OpenIddictApplicationDescriptor descriptor) =>
        new(
            descriptor.ClientType ?? "",
            !string.IsNullOrEmpty(descriptor.ClientSecret),
            descriptor.Permissions.ToHashSet(StringComparer.Ordinal),
            descriptor.Permissions
                .Where(permission => permission.StartsWith(
                    OpenIddictConstants.Permissions.Prefixes.Scope,
                    StringComparison.Ordinal))
                .Select(permission => permission[
                    OpenIddictConstants.Permissions.Prefixes.Scope.Length..])
                .ToHashSet(StringComparer.Ordinal),
            descriptor.RedirectUris
                .Select(uri => uri.OriginalString)
                .ToHashSet(StringComparer.Ordinal));

    private static void SetLogoutSettings(
        IDictionary<string, string> settings,
        IdentityClientManifest manifest)
    {
        if (manifest.FrontchannelLogoutUri is not null)
        {
            settings["frontchannel_logout_uri"] =
                manifest.FrontchannelLogoutUri.AbsoluteUri;
            settings["frontchannel_logout_session_required"] =
                manifest.FrontchannelLogoutSessionRequired ? "true" : "false";
        }

        if (manifest.BackchannelLogoutUri is not null)
        {
            settings["backchannel_logout_uri"] =
                manifest.BackchannelLogoutUri.AbsoluteUri;
            settings["backchannel_logout_session_required"] =
                manifest.BackchannelLogoutSessionRequired ? "true" : "false";
        }
    }

    private static void CopyManagedLogoutSettings(
        IDictionary<string, string> target,
        IDictionary<string, string> source)
    {
        foreach (var key in ManagedLogoutSettingKeys)
        {
            if (source.TryGetValue(key, out var value))
            {
                target[key] = value;
            }
            else
            {
                target.Remove(key);
            }
        }
    }

    private static bool ManagedLogoutSettingsEqual(
        IDictionary<string, string> current,
        IDictionary<string, string> desired) =>
        ManagedLogoutSettingKeys.All(key =>
            current.TryGetValue(key, out var currentValue) ==
            desired.TryGetValue(key, out var desiredValue) &&
            string.Equals(currentValue, desiredValue, StringComparison.Ordinal));

    private static bool ManifestPropertiesEqual(
        IDictionary<string, JsonElement> current,
        IDictionary<string, JsonElement> desired) =>
        GetInt32Property(current, SchemaVersionProperty) ==
        GetInt32Property(desired, SchemaVersionProperty) &&
        string.Equals(
            GetStringProperty(current, OwnerProperty),
            GetStringProperty(desired, OwnerProperty),
            StringComparison.Ordinal) &&
        string.Equals(
            GetStringProperty(current, ManifestIdentityProperty),
            GetStringProperty(desired, ManifestIdentityProperty),
            StringComparison.Ordinal) &&
        string.Equals(
            GetStringProperty(current, SecretReferenceProperty),
            GetStringProperty(desired, SecretReferenceProperty),
            StringComparison.Ordinal) &&
        NativeReturnUrisEqual(current, desired) &&
        ScopeEntitlementsEqual(current, desired);

    // Compared as a set: an entitlement list that only changed order is the
    // same policy and must not show up as a pending provisioning change.
    private static bool ScopeEntitlementsEqual(
        IDictionary<string, JsonElement> current,
        IDictionary<string, JsonElement> desired) =>
        ScopeEntitlements.Read(current.AsReadOnly())
            .ToHashSet()
            .SetEquals(ScopeEntitlements.Read(desired.AsReadOnly()));

    private static void SetManifestProperties(
        IDictionary<string, JsonElement> properties,
        int schemaVersion,
        string? secretReference,
        string manifestIdentity)
    {
        properties[SchemaVersionProperty] = JsonSerializer.SerializeToElement(schemaVersion);
        properties[OwnerProperty] = JsonSerializer.SerializeToElement(ProvisioningOwner);
        properties[ManifestIdentityProperty] =
            JsonSerializer.SerializeToElement(manifestIdentity);

        if (string.IsNullOrEmpty(secretReference))
        {
            properties.Remove(SecretReferenceProperty);
        }
        else
        {
            properties[SecretReferenceProperty] =
                JsonSerializer.SerializeToElement(secretReference);
        }
    }

    private static void CopyManifestProperties(
        IDictionary<string, JsonElement> target,
        IDictionary<string, JsonElement> source)
    {
        target[SchemaVersionProperty] = source[SchemaVersionProperty];

        target[OwnerProperty] = source[OwnerProperty];
        target[ManifestIdentityProperty] = source[ManifestIdentityProperty];

        if (source.TryGetValue(SecretReferenceProperty, out var secretReference))
        {
            target[SecretReferenceProperty] = secretReference;
        }
        else
        {
            target.Remove(SecretReferenceProperty);
        }

        if (source.TryGetValue(NativeReturnUriPolicy.PropertyKey, out var returnUris))
        {
            target[NativeReturnUriPolicy.PropertyKey] = returnUris;
        }
        else
        {
            target.Remove(NativeReturnUriPolicy.PropertyKey);
        }

        // Without this the entitlement would be written on create and silently
        // dropped on the next update, since only the keys named here survive a
        // managed merge.
        if (source.TryGetValue(ScopeEntitlements.PropertyName, out var entitlements))
        {
            target[ScopeEntitlements.PropertyName] = entitlements;
        }
        else
        {
            target.Remove(ScopeEntitlements.PropertyName);
        }
    }

    /// <summary>
    /// Writes the manifest's native callbacks into the client property bag,
    /// removing the key when the manifest declares none.
    /// </summary>
    private static void SetNativeReturnUris(
        IDictionary<string, JsonElement> properties,
        IReadOnlyList<string> values)
    {
        var normalized = values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (normalized.Length == 0)
        {
            properties.Remove(NativeReturnUriPolicy.PropertyKey);
            return;
        }

        properties[NativeReturnUriPolicy.PropertyKey] =
            JsonSerializer.SerializeToElement(normalized);
    }

    private static bool NativeReturnUrisEqual(
        IDictionary<string, JsonElement> current,
        IDictionary<string, JsonElement> desired) =>
        ReadNativeReturnUris(current).SequenceEqual(
            ReadNativeReturnUris(desired),
            StringComparer.Ordinal);

    private static IReadOnlyList<string> ReadNativeReturnUris(
        IDictionary<string, JsonElement> properties) =>
        properties.TryGetValue(NativeReturnUriPolicy.PropertyKey, out var value)
        && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray()
                .Where(element => element.ValueKind == JsonValueKind.String)
                .Select(element => element.GetString()!)
                .ToArray()
            : [];

    private static int? GetInt32Property(
        IDictionary<string, JsonElement> properties,
        string name) =>
        properties.TryGetValue(name, out var value) &&
        value.ValueKind == JsonValueKind.Number &&
        value.TryGetInt32(out var result)
            ? result
            : null;

    private static string? GetStringProperty(
        IDictionary<string, JsonElement> properties,
        string name) =>
        properties.TryGetValue(name, out var value) &&
        value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string GetManifestIdentity(
        string? manifestId,
        string fallback) =>
        string.IsNullOrWhiteSpace(manifestId)
            ? fallback
            : manifestId.Trim();
}
