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

public sealed record ClientDefinitionSnapshot(
    string ClientType,
    bool HasClientSecret,
    IReadOnlySet<string> GrantTypes,
    IReadOnlySet<string> ScopeNames,
    IReadOnlySet<string> RedirectUris);

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
    IReadOnlySet<string>? AllowedScopes = null,
    string? ActorSubject = null,
    ClientDefinitionSnapshot? Current = null,
    bool AuthorizeSensitiveTransitions = false);

public sealed record ClientDefinitionValidationIssue(
    string Code,
    string Field,
    string Message);

public sealed record ClientDefinitionValidationResult(
    IReadOnlyList<ClientDefinitionValidationIssue> Issues,
    ClientDefinitionRolloutMode RolloutMode = ClientDefinitionRolloutMode.Enforce)
{
    public bool IsValid => RolloutMode is ClientDefinitionRolloutMode.Observe
        || Issues.Count == 0;

    public bool HasObservedIssues =>
        RolloutMode is ClientDefinitionRolloutMode.Observe && Issues.Count > 0;

    public static ClientDefinitionValidationResult Valid { get; } =
        new([]);
}

public interface IClientDefinitionValidator
{
    bool RequiresProofKeyForCodeExchange(
        IReadOnlyCollection<string> grantTypes);

    ClientDefinitionValidationResult Validate(ClientDefinitionRequest request);
}

public interface IClientScopeGrantPolicy
{
    IReadOnlyList<ClientDefinitionValidationIssue> Validate(
        IReadOnlyCollection<string> grantTypes,
        IReadOnlyCollection<string> scopeNames);
}

public interface IClientDefinitionTransitionPolicy
{
    IReadOnlyList<ClientDefinitionValidationIssue> Validate(
        string? actorSubject,
        ClientDefinitionSnapshot current,
        ClientDefinitionSnapshot desired,
        bool authorizeSensitiveTransitions);
}

public sealed class ClientDefinitionTransitionPolicy(
    IReservedScopePolicy reservedScopes) : IClientDefinitionTransitionPolicy
{
    public IReadOnlyList<ClientDefinitionValidationIssue> Validate(
        string? actorSubject,
        ClientDefinitionSnapshot current,
        ClientDefinitionSnapshot desired,
        bool authorizeSensitiveTransitions)
    {
        var transitions = new List<(string Code, string Field, string Message)>();

        if (string.Equals(
                current.ClientType,
                "confidential",
                StringComparison.Ordinal)
            && string.Equals(
                desired.ClientType,
                "public",
                StringComparison.Ordinal))
        {
            transitions.Add((
                "confidential_to_public_requires_authorization",
                "clientType",
                "Converting a confidential client to public requires an explicit transition authorization."));
        }

        if (current.HasClientSecret && !desired.HasClientSecret)
        {
            transitions.Add((
                "secret_removal_requires_authorization",
                "clientSecret",
                "Removing a client secret requires an explicit transition authorization."));
        }

        if (!current.RedirectUris.SetEquals(desired.RedirectUris))
        {
            transitions.Add((
                "redirect_replacement_requires_authorization",
                "redirectUris",
                "Replacing redirect URIs requires an explicit transition authorization."));
        }

        var privilegedExpansion = desired.ScopeNames
            .Except(current.ScopeNames, StringComparer.Ordinal)
            .Any(reservedScopes.IsReserved);
        if (privilegedExpansion)
        {
            transitions.Add((
                "privileged_scope_expansion_requires_authorization",
                "scopes",
                "Expanding a client into a reserved scope requires an explicit transition authorization."));
        }

        if (transitions.Count == 0)
        {
            return [];
        }

        if (string.IsNullOrWhiteSpace(actorSubject))
        {
            return [new(
                "transition_actor_required",
                "actor",
                "Sensitive client transitions require an authenticated actor identity.")];
        }

        if (authorizeSensitiveTransitions)
        {
            return [];
        }

        return transitions
            .Select(transition => new ClientDefinitionValidationIssue(
                transition.Code,
                transition.Field,
                transition.Message))
            .ToArray();
    }
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
    IClientScopeGrantPolicy? scopeGrantPolicy = null,
    IClientDefinitionTransitionPolicy? transitionPolicy = null)
    : IClientDefinitionValidator
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

    public bool RequiresProofKeyForCodeExchange(
        IReadOnlyCollection<string> grantTypes)
    {
        ArgumentNullException.ThrowIfNull(grantTypes);
        return grantTypes.Any(IsAuthorizationCodeGrant);
    }

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
        var hasAuthorizationCode = RequiresProofKeyForCodeExchange(grants);

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

        if (hasAuthorizationCode && !request.RequirePkce)
        {
            issues.Add(new(
                "pkce_required",
                "requirements",
                "All authorization-code clients require PKCE."));
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

        if (request.Current is not null)
        {
            var desired = new ClientDefinitionSnapshot(
                request.ClientType,
                request.HasClientSecret,
                grants.ToHashSet(StringComparer.Ordinal),
                scopes.ToHashSet(StringComparer.Ordinal),
                request.RedirectUris
                    .Select(uri => uri.OriginalString)
                    .ToHashSet(StringComparer.Ordinal));
            issues.AddRange((transitionPolicy
                ?? new ClientDefinitionTransitionPolicy(reservedScopes)).Validate(
                request.ActorSubject,
                request.Current,
                desired,
                request.AuthorizeSensitiveTransitions));
        }

        return issues.Count == 0
            ? request.RolloutMode is ClientDefinitionRolloutMode.Enforce
                ? ClientDefinitionValidationResult.Valid
                : new([], request.RolloutMode)
            : new(issues, request.RolloutMode);
    }

    private static bool IsAuthorizationCodeGrant(string grant) =>
        string.Equals(grant, "authorization_code", StringComparison.Ordinal)
        || string.Equals(grant, "gt:authorization_code", StringComparison.Ordinal);

    private static bool IsClientCredentialsGrant(string grant) =>
        string.Equals(grant, "client_credentials", StringComparison.Ordinal)
        || string.Equals(grant, "gt:client_credentials", StringComparison.Ordinal);
}
