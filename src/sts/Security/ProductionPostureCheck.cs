using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
// ManagementOptions exists in both Sufficit.Identity.STS and
// Sufficit.Identity.Management; alias the management-layer one (which carries
// the Authorization policy modes this check inspects) to avoid ambiguity with
// the STS-layer type in this same namespace.
using ManagementOptions = Sufficit.Identity.Management.ManagementOptions;

namespace Sufficit.Identity.STS.Security;

/// <summary>
/// A single security-posture finding discovered at startup: a default that is
/// safe for development or a gradual rollout but leaves a protection in
/// report-only/permissive mode in production.
/// </summary>
/// <param name="Id">Stable identifier for the finding (used in logs/tests).</param>
/// <param name="Summary">One-line description of what is permissive.</param>
/// <param name="Remedy">How the operator makes the choice explicit.</param>
public sealed record ProductionPostureFinding(
    string Id,
    string Summary,
    string Remedy);

/// <summary>
/// Consolidated production go-live posture check. Several subsystems ship a
/// deliberately permissive default so a fresh install or a rolling migration
/// does not break: CSP runs Report-Only, the management authorization
/// object/principal policies run in Observe (log-only) mode, the DPoP replay
/// cache can be single-node, and JARM encryption may be off for FAPI clients.
/// Each is individually reasonable, but collectively they are easy to ship to
/// production unnoticed — the operator believes a protection is active when it
/// is only observing.
/// </summary>
/// <remarks>
/// This check gathers every such default into one place. Outside Development,
/// the default posture is FAIL-CLOSED: if any permissive default is still in
/// effect the host refuses to start until the operator makes the choice
/// explicit (either by hardening the setting or by acknowledging it). The
/// escape hatch is per-finding acknowledgement, not a blanket ignore — an
/// operator who genuinely runs a single replica, or who is mid-rollout, sets
/// the specific hardening/acknowledgement flag the finding names. Development
/// is never blocked.
/// </remarks>
public static class ProductionPostureCheck
{
    /// <summary>
    /// Evaluates the current configuration and returns every permissive-default
    /// finding still in effect. An empty list means the posture is hardened.
    /// Pure (never throws on policy grounds) so it is unit-testable; the
    /// throwing/logging decision lives in <see cref="Enforce"/>.
    /// </summary>
    /// <param name="options">The STS options.</param>
    /// <param name="management">
    /// The bound management options, or null when the management API is
    /// disabled (in which case its policies are not evaluated).
    /// </param>
    /// <param name="distributedCacheIsMemoryFallback">
    /// True when the registered <see cref="IDistributedCache"/> is the
    /// in-memory fallback (not shared across replicas).
    /// </param>
    public static IReadOnlyList<ProductionPostureFinding> Evaluate(
        SufficitIdentityOptions options,
        ManagementOptions? management,
        bool distributedCacheIsMemoryFallback)
    {
        ArgumentNullException.ThrowIfNull(options);

        var findings = new List<ProductionPostureFinding>();

        // --- CSP Report-Only ---
        // Report-Only emits violation reports but blocks nothing, so it gives
        // no browser-side XSS mitigation.
        if (options.Csp.Enabled
            && options.Csp.ReportOnly
            && !options.Csp.AcknowledgeReportOnly)
        {
            findings.Add(new ProductionPostureFinding(
                "csp-report-only",
                "Content-Security-Policy is in Report-Only mode: violations are "
                + "reported but not blocked, so the policy provides no XSS "
                + "mitigation.",
                "Set Sufficit:Identity:Csp:ReportOnly=false to enforce the "
                + "policy, or Sufficit:Identity:Csp:AcknowledgeReportOnly=true "
                + "to keep report-only deliberately during calibration."));
        }

        // --- Management authorization policies in Observe (log-only) mode ---
        if (management is { Enabled: true })
        {
            var objectAccess = management.Authorization.ObjectAccess;
            if (objectAccess.Mode == ManagementPolicyEnforcementMode.Observe
                && !objectAccess.AcknowledgeObserveInProduction)
            {
                findings.Add(new ProductionPostureFinding(
                    "management-object-access-observe",
                    "Management object-access policy is in Observe mode: "
                    + "context/tenant boundary violations are logged but "
                    + "permitted, so the boundary is not enforced.",
                    "Set Sufficit:Identity:Management:Authorization:ObjectAccess:Mode=Enforce, "
                    + "or AcknowledgeObserveInProduction=true if a single-context "
                    + "deployment genuinely needs no boundary."));
            }

            var protectedPrincipals = management.Authorization.ProtectedPrincipals;
            if (protectedPrincipals.Mode == ManagementPolicyEnforcementMode.Observe
                && !protectedPrincipals.AcknowledgeObserveInProduction)
            {
                findings.Add(new ProductionPostureFinding(
                    "management-protected-principal-observe",
                    "Management protected-principal policy is in Observe mode: "
                    + "privilege-escalation attempts against protected "
                    + "principals are logged but permitted.",
                    "Set Sufficit:Identity:Management:Authorization:ProtectedPrincipals:Mode=Enforce, "
                    + "or AcknowledgeObserveInProduction=true to accept the risk."));
            }
        }

        // --- DPoP replay cache not shared across replicas ---
        if (options.Dpop.Enabled
            && options.DistributedCache.RequireShared
            && distributedCacheIsMemoryFallback)
        {
            findings.Add(new ProductionPostureFinding(
                "dpop-replay-cache-not-shared",
                "DPoP is enabled and DistributedCache:RequireShared=true, but "
                + "the registered IDistributedCache is the in-memory fallback, "
                + "which is not shared across replicas — DPoP replay protection "
                + "degrades to per-replica.",
                "Register a shared cache (e.g. Redis via "
                + "AddStackExchangeRedisCache), or set "
                + "Sufficit:Identity:DistributedCache:RequireShared=false for a "
                + "genuine single-replica deployment."));
        }

        // --- JARM encryption off for FAPI-profiled clients ---
        if (options.Fapi2.Enabled
            && options.Fapi2.ClientIds.Count > 0
            && options.Jarm.Enabled
            && !options.Jarm.Encryption.Enabled
            && !options.Jarm.Encryption.AcknowledgeUnencryptedForFapi)
        {
            findings.Add(new ProductionPostureFinding(
                "jarm-unencrypted-for-fapi",
                "FAPI 2.0 is enabled for one or more clients but JARM "
                + "encryption is disabled: those clients receive signed-only "
                + "authorization responses instead of the encrypted responses "
                + "the FAPI 2.0 Advancing profile calls for.",
                "Set Sufficit:Identity:Jarm:Encryption:Enabled=true (clients "
                + "must register an encryption key), or "
                + "AcknowledgeUnencryptedForFapi=true to accept signed-only "
                + "responses for these clients."));
        }

        return findings;
    }

    /// <summary>
    /// Runs the posture check and enforces it. In Development, findings are
    /// logged at Warning and never block. Outside Development, findings block
    /// startup (fail-closed) unless <paramref name="failClosed"/> is false, in
    /// which case they are logged at Warning. Resolves the live
    /// <see cref="IDistributedCache"/> and (if present) the bound
    /// <see cref="ManagementOptions"/> from the service provider.
    /// </summary>
    /// <exception cref="ProductionPostureException">
    /// Thrown outside Development when <paramref name="failClosed"/> is true and
    /// at least one permissive-default finding is in effect.
    /// </exception>
    public static void Enforce(
        IServiceProvider services,
        SufficitIdentityOptions options,
        bool isDevelopment,
        bool failClosed,
        ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        bool memoryFallback;
        ManagementOptions? management;
        using (var scope = services.CreateScope())
        {
            var cache = scope.ServiceProvider.GetService<IDistributedCache>();
            memoryFallback = cache?.GetType().Name is "MemoryDistributedCache";

            // Management options are only registered when the management API is
            // enabled; absent means "management disabled", so its policies do
            // not apply.
            management = scope.ServiceProvider
                .GetService<Microsoft.Extensions.Options.IOptions<ManagementOptions>>()
                ?.Value;
        }

        var findings = Evaluate(options, management, memoryFallback);
        if (findings.Count == 0)
        {
            logger.LogInformation(
                "Production posture check passed: no permissive security "
                + "defaults are in effect.");
            return;
        }

        if (isDevelopment || !failClosed)
        {
            foreach (var finding in findings)
            {
                logger.LogWarning(
                    "Security posture finding [{FindingId}]: {Summary} Remedy: {Remedy}",
                    finding.Id, finding.Summary, finding.Remedy);
            }

            if (!isDevelopment)
            {
                logger.LogWarning(
                    "Production posture check found {Count} permissive "
                    + "default(s) but fail-closed is disabled "
                    + "(Sufficit:Identity:Security:FailClosedOnInsecureDefaults=false); "
                    + "starting anyway.",
                    findings.Count);
            }

            return;
        }

        // Fail-closed: refuse to start until every finding is resolved or
        // explicitly acknowledged.
        var detail = string.Join(
            Environment.NewLine,
            findings.Select(f => $"  - [{f.Id}] {f.Summary} Remedy: {f.Remedy}"));

        throw new ProductionPostureException(
            findings,
            "Refusing to start: the production security posture check found "
            + $"{findings.Count} permissive default(s) still in effect:"
            + Environment.NewLine + detail + Environment.NewLine
            + "Resolve or acknowledge each finding above, or set "
            + "Sufficit:Identity:Security:FailClosedOnInsecureDefaults=false to "
            + "downgrade this to a warning (not recommended for production).");
    }
}

/// <summary>
/// Thrown when the fail-closed production posture check finds unresolved
/// permissive defaults. Carries the findings so a host can surface them.
/// </summary>
public sealed class ProductionPostureException(
    IReadOnlyList<ProductionPostureFinding> findings,
    string message) : Exception(message)
{
    public IReadOnlyList<ProductionPostureFinding> Findings { get; } = findings;
}
