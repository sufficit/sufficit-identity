namespace Sufficit.Identity.Application.Security;

public enum ClientDefinitionSource
{
    Management,
    Provisioning,
    DynamicRegistration,
}

public enum ClientDefinitionRolloutMode
{
    Observe,
    Enforce,
}

public sealed record ClientDefinitionRequest(
    ClientDefinitionSource Source,
    string? ClientId,
    string ClientType,
    IReadOnlyCollection<string> GrantTypes,
    IReadOnlyCollection<string> ScopeNames,
    IReadOnlyCollection<Uri> RedirectUris,
    bool RequirePkce,
    bool HasClientSecret,
    ClientDefinitionRolloutMode RolloutMode = ClientDefinitionRolloutMode.Enforce,
    IReadOnlySet<string>? AllowedGrantTypes = null,
    IReadOnlySet<string>? AllowedScopes = null);

public sealed record ClientDefinitionValidationIssue(
    string Code,
    string Field,
    string Message);

public sealed record ClientDefinitionValidationResult(
    IReadOnlyList<ClientDefinitionValidationIssue> Issues)
{
    public bool IsValid => Issues.Count == 0;

    public static ClientDefinitionValidationResult Valid { get; } =
        new([]);
}

public interface IClientDefinitionValidator
{
    ClientDefinitionValidationResult Validate(ClientDefinitionRequest request);
}

public interface IClientScopeGrantPolicy
{
    IReadOnlyList<ClientDefinitionValidationIssue> Validate(
        IReadOnlyCollection<string> grantTypes,
        IReadOnlyCollection<string> scopeNames);
}

public sealed class ClientScopeGrantPolicy : IClientScopeGrantPolicy
{
    public IReadOnlyList<ClientDefinitionValidationIssue> Validate(
        IReadOnlyCollection<string> grantTypes,
        IReadOnlyCollection<string> scopeNames)
    {
        var canonicalGrants = grantTypes
            .Select(CanonicalizeGrant)
            .ToHashSet(StringComparer.Ordinal);
        var issues = new List<ClientDefinitionValidationIssue>();

        if (scopeNames.Contains(
                "offline_access",
                StringComparer.Ordinal)
            && !canonicalGrants.Contains("refresh_token"))
        {
            issues.Add(new(
                "offline_access_requires_refresh_token",
                "grantTypes",
                "offline_access requires the refresh_token grant."));
        }

        return issues;
    }

    private static string CanonicalizeGrant(string grant) =>
        grant.StartsWith("gt:", StringComparison.Ordinal)
            ? grant["gt:".Length..]
            : grant;
}

/// <summary>
/// Shared reserved-scope boundary used by management, provisioning and
/// dynamic registration. Privileged scopes are provisioned deliberately and
/// cannot be minted through an ordinary client CRUD request.
/// </summary>
public interface IReservedScopePolicy
{
    IReadOnlySet<string> Names { get; }

    bool IsReserved(string scope);
}

public sealed class ReservedScopePolicy : IReservedScopePolicy
{
    public ReservedScopePolicy(IEnumerable<string> names)
    {
        Names = names
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Select(name => name.Trim())
            .ToHashSet(StringComparer.Ordinal);
    }

    public IReadOnlySet<string> Names { get; }

    public bool IsReserved(string scope) =>
        !string.IsNullOrWhiteSpace(scope) && Names.Contains(scope);
}

/// <summary>
/// Shared protocol boundary for management CRUD, declarative provisioning and
/// dynamic client registration. Adapters remain responsible for translating
/// their transport models into this request and for reporting field errors.
/// </summary>
public sealed class ClientDefinitionValidator(
    IReservedScopePolicy reservedScopes,
    IClientScopeGrantPolicy? scopeGrantPolicy = null) : IClientDefinitionValidator
{
    private static readonly IReadOnlySet<string> SupportedGrantTypes =
        new HashSet<string>(StringComparer.Ordinal)
        {
            "authorization_code",
            "client_credentials",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "password",
            "implicit",
            "gt:authorization_code",
            "gt:client_credentials",
            "gt:refresh_token",
            "gt:urn:ietf:params:oauth:grant-type:device_code",
            "gt:urn:ietf:params:oauth:grant-type:token-exchange",
            "gt:password",
            "gt:implicit",
        };

    public ClientDefinitionValidationResult Validate(
        ClientDefinitionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var issues = new List<ClientDefinitionValidationIssue>();
        var grants = request.GrantTypes
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        foreach (var grant in grants)
        {
            if (!SupportedGrantTypes.Contains(grant))
            {
                issues.Add(new(
                    "unsupported_grant_type",
                    "grantTypes",
                    $"Grant type '{grant}' is not supported."));
            }

            if (request.AllowedGrantTypes is not null
                && !request.AllowedGrantTypes.Contains(grant))
            {
                issues.Add(new(
                    "grant_type_not_allowed",
                    "grantTypes",
                    $"Grant type '{grant}' is not allowed for this registration source."));
            }
        }

        var scopes = request.ScopeNames
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.StartsWith(
                    "oi_scp:",
                    StringComparison.Ordinal)
                ? value["oi_scp:".Length..]
                : value.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        issues.AddRange((scopeGrantPolicy ?? new ClientScopeGrantPolicy()).Validate(
            grants,
            scopes));

        foreach (var scope in scopes)
        {
            if (reservedScopes.IsReserved(scope))
            {
                issues.Add(new(
                    "scope_reserved",
                    "scopes",
                    $"Scope '{scope}' is reserved for a managed security boundary."));
            }

            if (request.AllowedScopes is not null
                && !request.AllowedScopes.Contains(scope))
            {
                issues.Add(new(
                    "scope_not_allowed",
                    "scopes",
                    $"Scope '{scope}' is not allowed for this registration source."));
            }
        }

        var isPublic = string.Equals(
            request.ClientType,
            "public",
            StringComparison.Ordinal);
        var hasClientCredentials = grants.Any(IsClientCredentialsGrant);
        var hasAuthorizationCode = grants.Any(IsAuthorizationCodeGrant);

        if (isPublic && request.HasClientSecret)
        {
            issues.Add(new(
                "public_client_secret",
                "clientSecret",
                "Public clients cannot carry a client secret."));
        }

        if (hasClientCredentials && isPublic)
        {
            issues.Add(new(
                "client_credentials_requires_confidential",
                "clientType",
                "client_credentials requires a confidential client."));
        }

        if (hasAuthorizationCode && isPublic && !request.RequirePkce)
        {
            issues.Add(new(
                "pkce_required",
                "requirements",
                "Public authorization-code clients require PKCE."));
        }

        foreach (var redirect in request.RedirectUris)
        {
            var isLoopback = redirect.IsLoopback
                || string.Equals(
                    redirect.Host,
                    "localhost",
                    StringComparison.OrdinalIgnoreCase);
            if (!redirect.IsAbsoluteUri
                || redirect.Fragment.Length > 0
                || (!string.Equals(
                        redirect.Scheme,
                        Uri.UriSchemeHttps,
                        StringComparison.OrdinalIgnoreCase)
                    && !isLoopback))
            {
                issues.Add(new(
                    "redirect_uri_invalid",
                    "redirectUris",
                    "Redirect URIs must be absolute HTTPS URIs (HTTP is allowed only for loopback) without fragments."));
            }
        }

        return issues.Count == 0
            ? ClientDefinitionValidationResult.Valid
            : new(issues);
    }

    private static bool IsAuthorizationCodeGrant(string grant) =>
        string.Equals(grant, "authorization_code", StringComparison.Ordinal)
        || string.Equals(grant, "gt:authorization_code", StringComparison.Ordinal);

    private static bool IsClientCredentialsGrant(string grant) =>
        string.Equals(grant, "client_credentials", StringComparison.Ordinal)
        || string.Equals(grant, "gt:client_credentials", StringComparison.Ordinal);
}
