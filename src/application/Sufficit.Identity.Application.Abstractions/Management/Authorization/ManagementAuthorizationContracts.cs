using System.Security.Claims;

namespace Sufficit.Identity.Management.Authorization;

public static class ManagementCapabilities
{
    public const string ClientsRead = "identity.clients.read";
    public const string ClientsCreate = "identity.clients.create";
    public const string ClientsUpdate = "identity.clients.update";
    public const string ClientsDelete = "identity.clients.delete";
    public const string BrandingRead = "identity.branding.read";
    public const string BrandingManage = "identity.branding.manage";
    public const string UsersRead = "identity.users.read";
    public const string UsersCreate = "identity.users.create";
    public const string UsersUpdate = "identity.users.update";
    public const string UsersDisable = "identity.users.disable";
    public const string UsersDelete = "identity.users.delete";
    public const string UsersReset = "identity.users.reset";

    /// <summary>
    /// Resends the account-confirmation email to an arbitrary user. Gated by
    /// its own capability (eval 2026-08-14, F-8) because it is an outbound
    /// mail action, not a read: riding on <see cref="UsersRead"/> let a
    /// read-only operator trigger unlimited account emails (mail-bombing
    /// vector) with no audit row of its own.
    /// </summary>
    public const string UsersResendConfirmation =
        "identity.users.resend_confirmation";
    public const string ClaimsRead = "identity.claims.read";
    public const string ClaimsCreate = "identity.claims.create";
    public const string ClaimsUpdate = "identity.claims.update";
    public const string ClaimsDelete = "identity.claims.delete";
    public const string ScopesRead = "identity.scopes.read";
    public const string ScopesCreate = "identity.scopes.create";
    public const string ScopesUpdate = "identity.scopes.update";
    public const string ScopesDelete = "identity.scopes.delete";
    public const string SessionsRead = "identity.sessions.read";
    public const string SessionsRevoke = "identity.sessions.revoke";
    public const string AuthorizationsRead = "identity.authorizations.read";
    public const string AuthorizationsRevoke =
        "identity.authorizations.revoke";
    public const string AuditRead = "identity.audit.read";
    public const string DatabaseRead = "identity.database.read";
    public const string MetricsRead = "identity.metrics.read";
    public const string MetricsManage = "identity.metrics.manage";
    public const string VaultSecretsRead = "identity.vault.secrets.read";
    public const string VaultSecretsManage = "identity.vault.secrets.manage";
    /// <summary>Plaintext disclosure of a named secret. Deliberately separate
    /// from <see cref="VaultSecretsRead"/> (metadata only) so service
    /// principals that resolve secrets need an explicit grant.</summary>
    public const string VaultSecretsResolve = "identity.vault.secrets.resolve";
    public const string ProvisioningPreview =
        "identity.provisioning.preview";
    public const string ProvisioningApply =
        "identity.provisioning.apply";
    public const string ManagementTokensRead =
        "identity.management.tokens.read";
    public const string ManagementTokensIssue =
        "identity.management.tokens.issue";
    public const string ManagementTokensRevoke =
        "identity.management.tokens.revoke";

    [Obsolete($"Use {nameof(UsersReset)}.")]
    public const string UsersResetPassword = UsersReset;

    [Obsolete($"Use {nameof(ManagementTokensRead)}.")]
    public const string OperatorTokensRead = ManagementTokensRead;

    [Obsolete($"Use {nameof(ManagementTokensIssue)}.")]
    public const string OperatorTokensIssue = ManagementTokensIssue;

    [Obsolete($"Use {nameof(ManagementTokensRevoke)}.")]
    public const string OperatorTokensRevoke = ManagementTokensRevoke;

    public static IReadOnlySet<string> All { get; } =
        new HashSet<string>(
            [
                ClientsRead,
                ClientsCreate,
                ClientsUpdate,
                ClientsDelete,
                BrandingRead,
                BrandingManage,
                UsersRead,
                UsersCreate,
                UsersUpdate,
                UsersDisable,
                UsersDelete,
                UsersReset,
                UsersResendConfirmation,
                ClaimsRead,
                ClaimsCreate,
                ClaimsUpdate,
                ClaimsDelete,
                ScopesRead,
                ScopesCreate,
                ScopesUpdate,
                ScopesDelete,
                SessionsRead,
                SessionsRevoke,
                AuthorizationsRead,
                AuthorizationsRevoke,
                AuditRead,
                DatabaseRead,
                MetricsRead,
                MetricsManage,
                VaultSecretsRead,
                VaultSecretsManage,
                VaultSecretsResolve,
                ProvisioningPreview,
                ProvisioningApply,
                ManagementTokensRead,
                ManagementTokensIssue,
                ManagementTokensRevoke
            ],
            StringComparer.Ordinal);

    /// <summary>
    /// Maps retired capability spellings to their canonical identifiers. This
    /// bounded compatibility bridge protects already-issued short-lived tokens
    /// and deployment role mappings while all new output uses <see cref="All"/>.
    /// </summary>
    public static string Normalize(string capability) => capability switch
    {
        "identity.users.reset-password" => UsersReset,
        "identity.operator-tokens.read" => ManagementTokensRead,
        "identity.operator-tokens.issue" => ManagementTokensIssue,
        "identity.operator-tokens.revoke" => ManagementTokensRevoke,
        _ => capability,
    };
}

public static class ManagementResourceTypes
{
    public const string Client = "client";
    public const string ClientCollection = "client-collection";
    public const string BrandingTheme = "branding-theme";
    public const string BrandingCollection = "branding-collection";
    public const string User = "user";
    public const string UserCollection = "user-collection";
    public const string Claim = "claim";
    public const string ClaimCollection = "claim-collection";
    public const string Scope = "scope";
    public const string ScopeCollection = "scope-collection";
    public const string Session = "session";
    public const string SessionCollection = "session-collection";
    public const string Authorization = "authorization";
    public const string AuthorizationCollection = "authorization-collection";
    public const string Audit = "audit";
    public const string DatabaseRuntime = "database-runtime";
    public const string Overview = "overview";
    public const string Metrics = "metrics";
    public const string VaultSecrets = "vault-secrets";
    public const string VaultSecretCollection = "vault-secret-collection";
    public const string VaultUser = "vault-user";
    public const string VaultUserCollection = "vault-user-collection";
    public const string Provisioning = "provisioning";
    public const string OperatorToken = "operator-token";
    public const string OperatorTokenCollection = "operator-token-collection";
}

public sealed record ManagementRequestContext(
    ClaimsPrincipal Operator,
    string CorrelationId)
{
    public string OperatorSubject =>
        Operator.FindFirst("sub")?.Value
        ?? Operator.FindFirst(ClaimTypes.NameIdentifier)?.Value
        ?? "unknown";

    public string? OperatorDisplayName =>
        Operator.Identity?.Name
        ?? Operator.FindFirst(ClaimTypes.Email)?.Value;

    public string? AuthenticationMethods
    {
        get
        {
            var values = Operator.FindAll("amr")
                .SelectMany(claim => claim.Value.Split(
                    ' ',
                    StringSplitOptions.RemoveEmptyEntries))
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray();

            return values.Length is 0 ? null : string.Join(' ', values);
        }
    }
}

/// <summary>
/// Object-level authorization target. The former <c>TenantId</c> parameter was
/// removed with the internal multi-tenant system (2026-08 decision, eval F-6):
/// spawning a complete new application (docker) and sharing hardware is cheap,
/// and external isolation per deployment is both stronger and simpler than a
/// row-level tenant boundary. Object-level authorization now means protected
/// principals; vault secret contexts remain as pure data organization.
/// </summary>
public sealed record ManagementResource(
    string Type,
    string? Id = null);

public enum ManagementAuthorizationOutcome
{
    Allowed,
    Denied,
    StepUpRequired
}

public sealed record ManagementAuthorizationDecision(
    ManagementAuthorizationOutcome Outcome,
    string ReasonCode,
    string? RequiredCapability = null)
{
    public bool IsAllowed => Outcome is ManagementAuthorizationOutcome.Allowed;

    public static ManagementAuthorizationDecision Allowed(
        string reasonCode = "allowed") =>
        new(ManagementAuthorizationOutcome.Allowed, reasonCode);

    public static ManagementAuthorizationDecision Denied(
        string reasonCode,
        string? requiredCapability = null) =>
        new(
            ManagementAuthorizationOutcome.Denied,
            reasonCode,
            requiredCapability);

    public static ManagementAuthorizationDecision StepUpRequired(
        string reasonCode,
        string? requiredCapability = null) =>
        new(
            ManagementAuthorizationOutcome.StepUpRequired,
            reasonCode,
            requiredCapability);
}

public interface IManagementAuthorizationEvaluator
{
    ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
        ClaimsPrincipal principal,
        string capability,
        ManagementResource resource,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementEntitlements(
    IReadOnlySet<string> Capabilities,
    IReadOnlySet<string>? MultiFactorExempt = null)
{
    public bool Contains(string capability) =>
        Capabilities.Contains(capability);

    /// <summary>
    /// Esta capacidade foi concedida a um principal de MÁQUINA, e por isso não
    /// tem segundo fator a apresentar.
    ///
    /// Quem resolve a concessão é quem sabe COMO ela foi concedida, e por isso
    /// a exceção mora aqui e não numa política por recurso: a política vê o
    /// recurso, não a origem da capacidade.
    ///
    /// Vazio por padrão. Um principal humano nunca entra aqui, então a
    /// exigência de MFA continua exatamente como estava para ele.
    /// </summary>
    public bool IsMultiFactorExempt(string capability) =>
        MultiFactorExempt?.Contains(capability) is true;
}

public interface IManagementEntitlementResolver
{
    ValueTask<ManagementEntitlements> ResolveAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementAccessPolicy(bool RequireMfa);

public interface IManagementAccessPolicyProvider
{
    ValueTask<ManagementAccessPolicy> GetAsync(
        ManagementResource resource,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Object-level authorization boundary (BOLA). Consulted by the authorization
/// evaluator AFTER the capability check and the MFA step-up check pass, to
/// decide whether the operator may exercise <paramref name="capability"/>
/// against this specific <paramref name="resource"/> — e.g. protected
/// principals ("can this operator disable *this* user"). The tenant-scoping
/// half of this seam was removed with the internal multi-tenant system
/// (2026-08 decision): isolation is per deployment, externally.
/// </summary>
/// <remarks>
/// The default implementation fails closed. Hosts must register a concrete
/// policy; missing composition can never become blanket access.
/// </remarks>
public interface IManagementObjectAccessPolicy
{
    ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
        ClaimsPrincipal principal,
        string capability,
        ManagementResource resource,
        CancellationToken cancellationToken = default);
}

public interface IProtectedPrincipalAccessPolicy
{
    ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
        ClaimsPrincipal principal,
        string capability,
        string targetUserId,
        CancellationToken cancellationToken = default);
}

public enum ManagementPolicyEnforcementMode
{
    Observe,
    Enforce,
}

public sealed class ProtectedPrincipalAccessOptions
{
    public ManagementPolicyEnforcementMode Mode { get; set; } =
        ManagementPolicyEnforcementMode.Enforce;

    public string TierClaimType { get; set; } = "identity_principal_tier";

    public string[] ProtectedUserIds { get; set; } = [];

    public string[] ProtectedRoles { get; set; } = [];

    public string BreakGlassClaimType { get; set; } =
        "identity_break_glass";

    public string BreakGlassClaimValue { get; set; } =
        "identity.management";

    /// <summary>
    /// Acknowledges that running this policy in <see cref="Mode"/> =
    /// <see cref="ManagementPolicyEnforcementMode.Observe"/> in production is a
    /// deliberate choice. When false (default), the production posture check
    /// flags Observe mode as an unresolved permissive default — privilege-
    /// escalation attempts against protected principals are logged but
    /// permitted.
    /// </summary>
    public bool AcknowledgeObserveInProduction { get; set; }
}

public sealed class ManagementAuthorizationOptions
{
    public ProtectedPrincipalAccessOptions ProtectedPrincipals { get; set; } =
        new();

    public VaultSecretAccessOptions VaultSecrets { get; set; } = new();

    /// <summary>
    /// Deployment-specific roles that receive every management capability
    /// (full administrator). <b>Use sparingly.</b> Every principal in any of
    /// these roles bypasses per-capability checks and gets every capability.
    /// Default is empty (no god-mode) — set explicitly to grant blanket access.
    /// </summary>
    public string[] FullAdministratorRoles { get; set; } = [];

    /// <summary>
    /// Maps a role name to the set of capabilities it grants. This is the
    /// granular alternative to <see cref="FullAdministratorRoles"/>: a role
    /// like <c>identity-user-manager</c> can map to
    /// <c>[identity.users.read, identity.users.create, identity.users.update]</c>
    /// without granting client/scope/provisioning capabilities. Default is
    /// empty — configure per environment.
    /// </summary>
    public Dictionary<string, string[]> RoleCapabilities { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Claim types that carry exact management capability names (e.g.
    /// <c>identity.users.read</c>). <b>Must NOT include <c>"scope"</c></b>:
    /// the OAuth <c>scope</c> claim carries OAuth scope values (like
    /// <c>identity.management</c>), which are a different namespace from
    /// management capabilities. Mixing the two would let an OAuth scope
    /// accidentally grant a management capability.
    /// </summary>
    public string[] CapabilityClaimTypes { get; set; } =
        ["permission"];

    /// <summary>
    /// Nome da propriedade, no registro do cliente, que lista os papéis dele.
    ///
    /// A CONCESSÃO mora no banco, junto com o cliente, exatamente como a de um
    /// humano mora em <c>userroles</c>. O que o papel SIGNIFICA continua em
    /// <see cref="RoleCapabilities"/>, que é config revisada. É a mesma divisão
    /// que já valia para gente: o banco diz quem é o quê, a configuração diz o
    /// que isso permite.
    ///
    /// Pôr a concessão em configuração pareceu mais simples e não era: revogar
    /// o acesso de um serviço comprometido passaria a exigir uma implantação,
    /// e implantação é justamente o que quebra primeiro num dia ruim.
    /// </summary>
    public string ClientRolesPropertyName { get; set; } =
        "identity:client:roles";
}

/// <summary>
/// Onde o <c>client_id</c> aparece num principal vindo de um access token.
/// <c>azp</c> entra como alternativa porque é o que alguns emissores usam
/// quando o token é para outra audiência.
/// </summary>
public static class ManagementPrincipal
{
    private static readonly string[] ClientIdClaimTypes = ["client_id", "azp"];

    public static string? ClientId(ClaimsPrincipal principal) =>
        ClientIdClaimTypes
            .Select(type => principal.FindFirst(type)?.Value)
            .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));

    /// <summary>
    /// Um principal de MÁQUINA — autenticado por segredo de cliente, sem
    /// usuário por trás. É o <c>sub</c> igual ao <c>client_id</c> que
    /// distingue: o handler de client_credentials põe o próprio client_id como
    /// subject, porque não há mais ninguém para pôr.
    /// </summary>
    public static bool IsService(ClaimsPrincipal principal)
    {
        var clientId = ClientId(principal);
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return false;
        }

        var subject = principal.FindFirst("sub")?.Value
            ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        return string.Equals(subject, clientId, StringComparison.Ordinal);
    }
}

/// <summary>Independent namespace and break-glass claims for named secrets.
/// These claims are issued by deployment policy and are not mutable through
/// the generic Management APIs.</summary>
public sealed class VaultSecretAccessOptions
{
    public string NamespaceClaimType { get; set; } =
        "identity_vault_namespace";

    public string BreakGlassClaimType { get; set; } =
        "identity_vault_break_glass";

    public string BreakGlassClaimValue { get; set; } =
        "identity.vault.secrets";
}

public sealed class ManagementAccessException(
    ManagementAuthorizationDecision decision) : Exception(decision.ReasonCode)
{
    public ManagementAuthorizationDecision Decision { get; } = decision;
}

public sealed class ManagementValidationException(
    string reasonCode,
    string message,
    string? field = null) : Exception(message)
{
    public string ReasonCode { get; } = reasonCode;

    public string? Field { get; } = field;
}

public sealed class ManagementConflictException(
    string reasonCode,
    string message) : Exception(message)
{
    public string ReasonCode { get; } = reasonCode;
}

public sealed class ManagementNotFoundException(
    string reasonCode,
    string message) : Exception(message)
{
    public string ReasonCode { get; } = reasonCode;
}
