using System.Text.RegularExpressions;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Management.Provisioning;

/// <summary>
/// Validates the migration manifest before any database access. The accepted
/// grant/response types intentionally represent the target architecture and
/// exclude implicit, hybrid and resource-owner-password flows for new
/// provisioning manifests. This validation does not remove runtime compatibility
/// for existing clients enabled through the explicit legacy-grant flags.
/// </summary>
public static partial class IdentityProvisioningManifestValidator
{
    private static readonly HashSet<string> AllowedClientTypes =
    [
        ManifestClientTypes.Public,
        ManifestClientTypes.Confidential,
    ];

    private static readonly HashSet<string> AllowedConsentTypes =
    [
        ManifestConsentTypes.Explicit,
        ManifestConsentTypes.External,
        ManifestConsentTypes.Implicit,
        ManifestConsentTypes.Systematic,
    ];

    private static readonly HashSet<string> AllowedGrantTypes =
    [
        ManifestGrantTypes.AuthorizationCode,
        ManifestGrantTypes.ClientCredentials,
        ManifestGrantTypes.DeviceCode,
        ManifestGrantTypes.RefreshToken,
        ManifestGrantTypes.TokenExchange,
    ];

    private static readonly HashSet<string> AllowedResponseTypes =
    [
        ManifestResponseTypes.Code,
    ];

    private static readonly HashSet<string> StandardScopes =
    [
        "address",
        "email",
        "offline_access",
        "openid",
        "phone",
        "profile",
        "roles",
    ];

    public static IReadOnlyList<string> Validate(
        IdentityProvisioningManifest? manifest,
        IReservedScopePolicy? reservedScopePolicy = null,
        IClientDefinitionValidator? clientDefinitionValidator = null)
    {
        var errors = new List<string>();
        reservedScopePolicy ??= new ReservedScopePolicy(
            ["identity.management", "scim"]);
        clientDefinitionValidator ??= new ClientDefinitionValidator(
            reservedScopePolicy);

        if (manifest is null)
        {
            errors.Add("The manifest body is required.");
            return errors;
        }

        if (manifest.SchemaVersion != IdentityProvisioningManifest.CurrentSchemaVersion)
        {
            errors.Add(
                $"schemaVersion must be {IdentityProvisioningManifest.CurrentSchemaVersion}; " +
                $"received {manifest.SchemaVersion}.");
        }

        if (!string.IsNullOrWhiteSpace(manifest.ManifestId))
        {
            ValidateIdentifier(manifest.ManifestId, 200, "manifestId", errors);
        }
        else if (manifest.RolloutMode is ClientDefinitionRolloutMode.Enforce)
        {
            errors.Add(
                "manifestId is required when rolloutMode is Enforce so ownership " +
                "and adoption decisions have a stable audit identity.");
        }

        if (manifest.Scopes is null)
        {
            errors.Add("scopes must be an array.");
        }

        if (manifest.Clients is null)
        {
            errors.Add("clients must be an array.");
        }

        var scopes = manifest.Scopes ?? [];
        var clients = manifest.Clients ?? [];
        var declaredScopes = new HashSet<string>(StringComparer.Ordinal);

        for (var index = 0; index < scopes.Count; index++)
        {
            var scope = scopes[index];
            var path = $"scopes[{index}]";

            if (scope is null)
            {
                errors.Add($"{path} must be an object.");
                continue;
            }

            ValidateIdentifier(scope.Name, 200, $"{path}.name", errors);

            if (!string.IsNullOrWhiteSpace(scope.Name) &&
                !declaredScopes.Add(scope.Name))
            {
                errors.Add($"{path}.name duplicates scope '{scope.Name}'.");
            }

            if (RetiredIdentityScopes.Contains(scope.Name))
            {
                errors.Add(
                    $"{path}.name references retired scope '{scope.Name}'.");
            }

            ValidateOptionalLength(scope.DisplayName, 200, $"{path}.displayName", errors);
            ValidateOptionalLength(scope.Description, 1000, $"{path}.description", errors);
            ValidateUniqueStrings(scope.Resources, $"{path}.resources", 100, errors);

            // An entitlement writes a claim onto every user who approves the
            // scope, so a blank type or value must be rejected here rather than
            // silently skipped at issuance.
            for (var claimIndex = 0;
                claimIndex < scope.EntitlementClaims.Count;
                claimIndex++)
            {
                var claim = scope.EntitlementClaims[claimIndex];
                var claimPath = $"{path}.entitlementClaims[{claimIndex}]";

                if (string.IsNullOrWhiteSpace(claim.Type))
                {
                    errors.Add($"{claimPath}.type is required.");
                }

                if (string.IsNullOrWhiteSpace(claim.Value))
                {
                    errors.Add($"{claimPath}.value is required.");
                }

                ValidateOptionalLength(claim.Type, 200, $"{claimPath}.type", errors);
                ValidateOptionalLength(claim.Value, 500, $"{claimPath}.value", errors);
            }
        }

        var declaredClients = new HashSet<string>(StringComparer.Ordinal);

        for (var index = 0; index < clients.Count; index++)
        {
            var client = clients[index];
            var path = $"clients[{index}]";

            if (client is null)
            {
                errors.Add($"{path} must be an object.");
                continue;
            }

            ValidateIdentifier(client.ClientId, 100, $"{path}.clientId", errors);

            if (!string.IsNullOrWhiteSpace(client.ClientId) &&
                !declaredClients.Add(client.ClientId))
            {
                errors.Add($"{path}.clientId duplicates client '{client.ClientId}'.");
            }

            ValidateOptionalLength(client.DisplayName, 200, $"{path}.displayName", errors);

            if (!AllowedClientTypes.Contains(client.ClientType))
            {
                errors.Add(
                    $"{path}.clientType must be one of: " +
                    $"{string.Join(", ", AllowedClientTypes.Order())}.");
            }

            if (!AllowedConsentTypes.Contains(client.ConsentType))
            {
                errors.Add(
                    $"{path}.consentType must be one of: " +
                    $"{string.Join(", ", AllowedConsentTypes.Order())}.");
            }

            ValidateUniqueStrings(client.GrantTypes, $"{path}.grantTypes", 200, errors);
            ValidateUniqueStrings(client.ResponseTypes, $"{path}.responseTypes", 100, errors);
            ValidateUniqueStrings(client.Scopes, $"{path}.scopes", 200, errors);

            foreach (var retiredScope in (client.Scopes ?? [])
                         .Where(RetiredIdentityScopes.Contains)
                         .Distinct(StringComparer.Ordinal))
            {
                errors.Add(
                    $"{path}.scopes contains retired scope '{retiredScope}'.");
            }

            var grants = new HashSet<string>(client.GrantTypes ?? [], StringComparer.Ordinal);
            var responseTypes = new HashSet<string>(
                client.ResponseTypes ?? [], StringComparer.Ordinal);

            var definitionValidation = clientDefinitionValidator.Validate(
                new ClientDefinitionRequest(
                    ClientDefinitionSource.Provisioning,
                    client.ClientId,
                    client.ClientType,
                    client.GrantTypes ?? [],
                    client.Scopes ?? [],
                    client.RedirectUris ?? [],
                    client.RequirePkce,
                    client.ClientType == ManifestClientTypes.Confidential));
            foreach (var issue in definitionValidation.Issues)
            {
                errors.Add($"{path}.{issue.Field}: {issue.Message}");
            }

            foreach (var grant in grants.Where(grant => !AllowedGrantTypes.Contains(grant)))
            {
                errors.Add(
                    $"{path}.grantTypes contains unsupported target grant '{grant}'. " +
                    "Implicit, hybrid and password flows are not accepted in new " +
                    "target manifests; migrate them before cutover while preserving " +
                    "runtime compatibility for existing clients where required.");
            }

            foreach (var responseType in responseTypes.Where(
                         responseType => !AllowedResponseTypes.Contains(responseType)))
            {
                errors.Add(
                    $"{path}.responseTypes contains unsupported target response type " +
                    $"'{responseType}'.");
            }

            if (grants.Count == 0)
            {
                errors.Add($"{path}.grantTypes must contain at least one target grant.");
            }

            var usesAuthorizationCode = grants.Contains(ManifestGrantTypes.AuthorizationCode);

            if (usesAuthorizationCode)
            {
                if (!client.RequirePkce)
                {
                    errors.Add(
                        $"{path}.requirePkce must be true for authorization_code clients.");
                }

                if (!responseTypes.SetEquals([ManifestResponseTypes.Code]))
                {
                    errors.Add(
                        $"{path}.responseTypes must contain only 'code' for " +
                        "authorization_code clients.");
                }

                if ((client.RedirectUris?.Count ?? 0) == 0)
                {
                    errors.Add(
                        $"{path}.redirectUris must contain at least one URI for " +
                        "authorization_code clients.");
                }
            }
            else
            {
                if (responseTypes.Count > 0)
                {
                    errors.Add(
                        $"{path}.responseTypes must be empty when authorization_code is absent.");
                }

                if (client.RequirePkce)
                {
                    errors.Add(
                        $"{path}.requirePkce requires the authorization_code grant.");
                }

                if ((client.RedirectUris?.Count ?? 0) > 0 ||
                    (client.PostLogoutRedirectUris?.Count ?? 0) > 0 ||
                    client.FrontchannelLogoutUri is not null ||
                    client.BackchannelLogoutUri is not null)
                {
                    errors.Add(
                        $"{path} cannot declare login/logout URIs without authorization_code.");
                }
            }

            if (grants.Contains(ManifestGrantTypes.ClientCredentials) &&
                client.ClientType != ManifestClientTypes.Confidential)
            {
                errors.Add(
                    $"{path}.clientType must be confidential for client_credentials.");
            }

            if ((client.Scopes ?? []).Contains("offline_access", StringComparer.Ordinal) &&
                !grants.Contains(ManifestGrantTypes.RefreshToken))
            {
                errors.Add(
                    $"{path}.grantTypes must include refresh_token when scopes includes " +
                    "offline_access.");
            }

            if (client.ClientType == ManifestClientTypes.Public &&
                !string.IsNullOrWhiteSpace(client.SecretReference))
            {
                errors.Add($"{path}.secretReference is not allowed for public clients.");
            }

            if (client.ClientType == ManifestClientTypes.Confidential)
            {
                if (string.IsNullOrWhiteSpace(client.SecretReference))
                {
                    errors.Add(
                        $"{path}.secretReference is required for confidential clients.");
                }
                else if (!SecretReferencePattern().IsMatch(client.SecretReference) ||
                         client.SecretReference.Contains("..", StringComparison.Ordinal) ||
                         client.SecretReference.Contains("//", StringComparison.Ordinal))
                {
                    errors.Add(
                        $"{path}.secretReference must be a logical secret-store path, " +
                        "not a credential value.");
                }
            }

            foreach (var scope in client.Scopes ?? [])
            {
                if (!StandardScopes.Contains(scope) && !declaredScopes.Contains(scope))
                {
                    errors.Add(
                        $"{path}.scopes references undeclared custom scope '{scope}'.");
                }
            }

            ValidateUris(
                client.RedirectUris,
                $"{path}.redirectUris",
                client.ClientType,
                errors);
            ValidateUris(
                client.PostLogoutRedirectUris,
                $"{path}.postLogoutRedirectUris",
                client.ClientType,
                errors);
            ValidateNativeReturnUris(
                client.NativeReturnUris,
                $"{path}.nativeReturnUris",
                errors);

            ValidateLogoutUri(
                client.FrontchannelLogoutUri,
                $"{path}.frontchannelLogoutUri",
                errors);
            ValidateLogoutUri(
                client.BackchannelLogoutUri,
                $"{path}.backchannelLogoutUri",
                errors);

            if (client.FrontchannelLogoutSessionRequired &&
                client.FrontchannelLogoutUri is null)
            {
                errors.Add(
                    $"{path}.frontchannelLogoutUri is required when " +
                    "frontchannelLogoutSessionRequired is true.");
            }

            if (client.BackchannelLogoutSessionRequired &&
                client.BackchannelLogoutUri is null)
            {
                errors.Add(
                    $"{path}.backchannelLogoutUri is required when " +
                    "backchannelLogoutSessionRequired is true.");
            }

            if (client.FrontchannelLogoutUri is not null &&
                !(client.RedirectUris ?? []).Any(redirect =>
                    SameOrigin(redirect, client.FrontchannelLogoutUri)))
            {
                errors.Add(
                    $"{path}.frontchannelLogoutUri must use the same scheme, " +
                    "host and port as a redirect URI.");
            }
        }

        return errors;
    }

    public static void ValidateAndThrow(
        IdentityProvisioningManifest? manifest,
        IReservedScopePolicy? reservedScopePolicy = null,
        IClientDefinitionValidator? clientDefinitionValidator = null)
    {
        var errors = Validate(
            manifest,
            reservedScopePolicy,
            clientDefinitionValidator);
        if (errors.Count > 0)
        {
            throw new IdentityProvisioningManifestException(errors);
        }
    }

    private static void ValidateIdentifier(
        string? value,
        int maxLength,
        string path,
        ICollection<string> errors)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            errors.Add($"{path} is required.");
            return;
        }

        if (!string.Equals(value, value.Trim(), StringComparison.Ordinal))
        {
            errors.Add($"{path} cannot start or end with whitespace.");
        }

        if (value.Length > maxLength)
        {
            errors.Add($"{path} cannot exceed {maxLength} characters.");
        }

        if (value.Any(char.IsControl))
        {
            errors.Add($"{path} cannot contain control characters.");
        }
    }

    private static void ValidateOptionalLength(
        string? value,
        int maxLength,
        string path,
        ICollection<string> errors)
    {
        if (value?.Length > maxLength)
        {
            errors.Add($"{path} cannot exceed {maxLength} characters.");
        }
    }

    private static void ValidateUniqueStrings(
        IReadOnlyCollection<string>? values,
        string path,
        int maxLength,
        ICollection<string> errors)
    {
        if (values is null)
        {
            errors.Add($"{path} must be an array.");
            return;
        }

        var unique = new HashSet<string>(StringComparer.Ordinal);

        foreach (var value in values)
        {
            ValidateIdentifier(value, maxLength, path, errors);
            if (!string.IsNullOrWhiteSpace(value) && !unique.Add(value))
            {
                errors.Add($"{path} contains duplicate value '{value}'.");
            }
        }
    }

    /// <summary>
    /// Validates the native callbacks a manifest registers. These are not
    /// redirection endpoints — they receive no code and no token — so a
    /// private-use URI scheme (RFC 8252, section 7.1) is acceptable, and the
    /// value is kept verbatim for the simple string comparison RFC 8252
    /// section 8.1 prescribes.
    /// </summary>
    private static void ValidateNativeReturnUris(
        IReadOnlyCollection<string>? values,
        string path,
        ICollection<string> errors)
    {
        if (values is null)
        {
            errors.Add($"{path} must be an array.");
            return;
        }

        if (values.Count > NativeReturnUriPolicy.MaximumRegistrations)
        {
            errors.Add(
                $"{path} accepts at most {NativeReturnUriPolicy.MaximumRegistrations} entries.");
        }

        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in values)
        {
            if (!NativeReturnUriPolicy.TryValidateRegistration(
                    value,
                    out var normalized,
                    out _,
                    out var reasonMessage))
            {
                errors.Add($"{path}: {reasonMessage}");
                continue;
            }

            if (!unique.Add(normalized!))
            {
                errors.Add($"{path} contains duplicate URI '{normalized}'.");
            }
        }
    }

    private static void ValidateUris(
        IReadOnlyCollection<Uri>? values,
        string path,
        string clientType,
        ICollection<string> errors)
    {
        if (values is null)
        {
            errors.Add($"{path} must be an array.");
            return;
        }

        var unique = new HashSet<string>(StringComparer.Ordinal);

        foreach (var uri in values)
        {
            if (uri is null || !uri.IsAbsoluteUri)
            {
                errors.Add($"{path} must contain only absolute URIs.");
                continue;
            }

            if (!unique.Add(uri.AbsoluteUri))
            {
                errors.Add($"{path} contains duplicate URI '{uri}'.");
            }

            if (!string.IsNullOrEmpty(uri.Fragment))
            {
                errors.Add($"{path} URI '{uri}' cannot contain a fragment.");
            }

            if (!string.IsNullOrEmpty(uri.UserInfo))
            {
                errors.Add($"{path} URI '{uri}' cannot contain user information.");
            }

            if (uri.Scheme == Uri.UriSchemeHttps)
            {
                continue;
            }

            if (uri.Scheme == Uri.UriSchemeHttp)
            {
                if (!uri.IsLoopback)
                {
                    errors.Add(
                        $"{path} URI '{uri}' must use HTTPS unless it is a loopback URI.");
                }

                continue;
            }

            if (DangerousCustomSchemes.Contains(uri.Scheme))
            {
                errors.Add(
                    $"{path} URI '{uri}' uses a forbidden redirect scheme.");
                continue;
            }

            if (clientType != ManifestClientTypes.Public)
            {
                errors.Add(
                    $"{path} custom-scheme URI '{uri}' is allowed only for public native clients.");
            }
        }
    }

    private static void ValidateLogoutUri(
        Uri? uri,
        string path,
        ICollection<string> errors)
    {
        if (uri is null)
        {
            return;
        }

        if (!uri.IsAbsoluteUri)
        {
            errors.Add($"{path} must be an absolute URI.");
            return;
        }

        if (uri.Fragment.Length > 0)
        {
            errors.Add($"{path} cannot contain a fragment.");
        }

        if (uri.UserInfo.Length > 0)
        {
            errors.Add($"{path} cannot contain user information.");
        }

        if (uri.Scheme != Uri.UriSchemeHttps &&
            !(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback))
        {
            errors.Add($"{path} must use HTTPS unless it is a loopback URI.");
        }
    }

    private static bool SameOrigin(Uri left, Uri right) =>
        left.IsAbsoluteUri &&
        right.IsAbsoluteUri &&
        string.Equals(left.Scheme, right.Scheme, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.Host, right.Host, StringComparison.OrdinalIgnoreCase) &&
        left.Port == right.Port;

    [GeneratedRegex(@"^[a-z0-9][a-z0-9._/-]{2,199}$", RegexOptions.CultureInvariant)]
    private static partial Regex SecretReferencePattern();

    private static readonly HashSet<string> DangerousCustomSchemes =
    [
        "data",
        "file",
        "ftp",
        "javascript",
        "mailto",
        "urn",
    ];
}
