using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Application.Security;

/// <summary>
/// Stable reason codes of the operator-aware scope-grant decision. They are a
/// public contract: audit rows, problem details and dashboards key on them.
/// </summary>
public static class ClientScopeGrantReasonCodes
{
    /// <summary>
    /// The scope is in the reserved floor (<c>ReservedApiScopes</c>). No
    /// operator, capability or rollout mode can grant it through a client
    /// definition; it is refused in <see cref="ClientDefinitionRolloutMode.Observe"/>
    /// as well.
    /// </summary>
    public const string ScopeReserved = "scope_reserved";

    /// <summary>
    /// The scope is a deployment-defined privileged scope and the operator
    /// does not hold the capability required to grant it.
    /// </summary>
    public const string CapabilityMissing = "scope_grant_capability_missing";

    /// <summary>
    /// The scope is a deployment-defined privileged scope and the request has
    /// no operator at all (dynamic client registration, an unauthenticated
    /// caller). Such a request is the most restricted principal there is.
    /// </summary>
    public const string OperatorRequired = "scope_grant_operator_required";
}

/// <summary>
/// One privileged scope and the Management capability an operator must hold
/// to put it on a client.
/// </summary>
public sealed class PrivilegedClientScope
{
    public string Scope { get; set; } = string.Empty;

    /// <summary>
    /// Capability the operator must hold. Empty means
    /// <see cref="ManagementCapabilities.ScopesGrant"/>.
    /// </summary>
    public string? Capability { get; set; }
}

/// <summary>
/// Deployment configuration of the operator-aware scope-grant decision,
/// bound from <c>Sufficit:Identity:Management:ClientScopeGrants</c> by every
/// client-definition entry point (Management, provisioning and dynamic
/// registration read the same section).
/// </summary>
public sealed class ClientScopeGrantOptions
{
    public const string ConfigurationSection =
        "Sufficit:Identity:Management:ClientScopeGrants";

    /// <summary>
    /// <see cref="ClientDefinitionRolloutMode.Observe"/> (default) records a
    /// would-be denial and allows the request;
    /// <see cref="ClientDefinitionRolloutMode.Enforce"/> refuses it. The
    /// reserved floor is enforced in both modes.
    /// </summary>
    public ClientDefinitionRolloutMode Mode { get; set; } =
        ClientDefinitionRolloutMode.Observe;

    /// <summary>
    /// Scopes that only an operator holding the mapped capability may grant.
    /// Empty by default: nothing beyond the reserved floor is privileged until
    /// a deployment says so.
    /// </summary>
    public List<PrivilegedClientScope> PrivilegedScopes { get; set; } = [];

    /// <summary>
    /// Fails composition on a configuration that could never be satisfied —
    /// a capability outside the catalog would make the scope ungrantable by
    /// anyone without anyone noticing.
    /// </summary>
    public IReadOnlyDictionary<string, string> ResolvePrivilegedScopes()
    {
        var resolved = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var entry in PrivilegedScopes ?? [])
        {
            var scope = entry?.Scope?.Trim();
            if (string.IsNullOrEmpty(scope))
            {
                throw new InvalidOperationException(
                    $"{ConfigurationSection}:PrivilegedScopes contains an entry without a scope.");
            }

            var capability = string.IsNullOrWhiteSpace(entry!.Capability)
                ? ManagementCapabilities.ScopesGrant
                : ManagementCapabilities.Normalize(entry.Capability.Trim());
            if (!ManagementCapabilities.All.Contains(capability))
            {
                throw new InvalidOperationException(
                    $"{ConfigurationSection}:PrivilegedScopes maps '{scope}' to "
                    + $"'{capability}', which is not a Management capability.");
            }

            if (!resolved.TryAdd(scope, capability))
            {
                throw new InvalidOperationException(
                    $"{ConfigurationSection}:PrivilegedScopes declares '{scope}' more than once.");
            }
        }

        return resolved;
    }
}

/// <summary>
/// Who is asking. Capabilities are the operator's RESOLVED Management
/// capabilities (roles, capability claims, an operator token's delegated
/// subset, a system user's roles), never the OAuth scopes of their token.
/// </summary>
public sealed record ClientScopeGrantOperator(
    string? Subject,
    IReadOnlySet<string> Capabilities)
{
    /// <summary>
    /// No operator: dynamic registration, or any caller that cannot name one.
    /// It holds nothing, so it can grant nothing privileged.
    /// </summary>
    public static ClientScopeGrantOperator None { get; } =
        new(null, new HashSet<string>(StringComparer.Ordinal));

    public bool IsPresent => !string.IsNullOrWhiteSpace(Subject);
}

/// <summary>
/// Input of the decision: operator, target client, grant types and scopes.
/// <paramref name="CurrentScopes"/> is what the client already holds — only
/// scopes outside it are an expansion that needs authority; keeping a
/// privileged scope an operator cannot grant is not an expansion.
/// </summary>
public sealed record ClientScopeGrantRequest(
    ClientDefinitionSource Source,
    ClientScopeGrantOperator Operator,
    string? ClientId,
    IReadOnlyCollection<string> GrantTypes,
    IReadOnlyCollection<string> RequestedScopes,
    IReadOnlyCollection<string>? CurrentScopes = null);

/// <summary>One scope the decision refuses (or, in Observe, would refuse).</summary>
public sealed record ClientScopeGrantDenial(
    string Scope,
    string ReasonCode,
    string? RequiredCapability,
    bool Enforced);

public sealed record ClientScopeGrantDecision(
    IReadOnlyList<ClientScopeGrantDenial> Denials,
    ClientDefinitionRolloutMode Mode,
    IReadOnlyList<string> GrantTypes)
{
    /// <summary>No enforced denial: the request may proceed.</summary>
    public bool IsAllowed => Denials.All(denial => !denial.Enforced);

    /// <summary>A denial was recorded but not enforced (Observe).</summary>
    public bool HasObservedDenials => Denials.Any(denial => !denial.Enforced);

    /// <summary>The denial a refusal reports first: enforced ones win.</summary>
    public ClientScopeGrantDenial? Primary =>
        Denials.FirstOrDefault(denial => denial.Enforced)
        ?? Denials.FirstOrDefault();
}

/// <summary>
/// The single scope-grant decision every client-definition entry point asks
/// before it persists scopes on a client.
/// </summary>
public interface IClientScopeGrantAuthorization
{
    ClientDefinitionRolloutMode Mode { get; }

    ClientScopeGrantDecision Decide(ClientScopeGrantRequest request);
}

/// <summary>
/// Default decision. Order of precedence, per scope:
/// <list type="number">
/// <item>reserved floor — refused always (<see cref="ClientScopeGrantReasonCodes.ScopeReserved"/>);</item>
/// <item>not privileged, or already on the client — allowed;</item>
/// <item>no operator — <see cref="ClientScopeGrantReasonCodes.OperatorRequired"/>;</item>
/// <item>operator lacks the mapped capability — <see cref="ClientScopeGrantReasonCodes.CapabilityMissing"/>.</item>
/// </list>
/// Items 3 and 4 are enforced only in <see cref="ClientDefinitionRolloutMode.Enforce"/>.
/// </summary>
public sealed class ClientScopeGrantAuthorization : IClientScopeGrantAuthorization
{
    private readonly IReservedScopePolicy _reserved;
    private readonly IReadOnlyDictionary<string, string> _privileged;

    public ClientScopeGrantAuthorization(
        IReservedScopePolicy reserved,
        ClientScopeGrantOptions? options = null)
    {
        _reserved = reserved;
        options ??= new ClientScopeGrantOptions();
        Mode = options.Mode;
        _privileged = options.ResolvePrivilegedScopes();
    }

    public ClientDefinitionRolloutMode Mode { get; }

    public IReadOnlyDictionary<string, string> PrivilegedScopes => _privileged;

    public ClientScopeGrantDecision Decide(ClientScopeGrantRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var grants = request.GrantTypes
            .Where(grant => !string.IsNullOrWhiteSpace(grant))
            .Select(grant => grant.Trim())
            .Select(grant => grant.StartsWith("gt:", StringComparison.Ordinal)
                ? grant["gt:".Length..]
                : grant)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var current = (request.CurrentScopes ?? [])
            .Select(NormalizeScope)
            .Where(scope => scope.Length > 0)
            .ToHashSet(StringComparer.Ordinal);
        var enforce = Mode is ClientDefinitionRolloutMode.Enforce;
        var denials = new List<ClientScopeGrantDenial>();

        foreach (var scope in request.RequestedScopes
                     .Select(NormalizeScope)
                     .Where(scope => scope.Length > 0)
                     .Distinct(StringComparer.Ordinal)
                     .Order(StringComparer.Ordinal))
        {
            if (_reserved.IsReserved(scope))
            {
                denials.Add(new(
                    scope,
                    ClientScopeGrantReasonCodes.ScopeReserved,
                    RequiredCapability: null,
                    Enforced: true));
                continue;
            }

            if (!_privileged.TryGetValue(scope, out var capability)
                || current.Contains(scope))
            {
                continue;
            }

            if (!request.Operator.IsPresent)
            {
                denials.Add(new(
                    scope,
                    ClientScopeGrantReasonCodes.OperatorRequired,
                    capability,
                    enforce));
            }
            else if (!request.Operator.Capabilities.Contains(capability))
            {
                denials.Add(new(
                    scope,
                    ClientScopeGrantReasonCodes.CapabilityMissing,
                    capability,
                    enforce));
            }
        }

        return new ClientScopeGrantDecision(denials, Mode, grants);
    }

    private static string NormalizeScope(string? scope)
    {
        var value = scope?.Trim() ?? string.Empty;
        foreach (var prefix in new[] { "scp:", "oi_scp:" })
        {
            if (value.StartsWith(prefix, StringComparison.Ordinal))
            {
                return value[prefix.Length..];
            }
        }

        return value;
    }
}
