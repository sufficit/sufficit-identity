namespace Sufficit.Identity.Application.Security;

/// <summary>How a posture finding affects startup outside Development.</summary>
public enum ProductionPostureSeverity
{
    /// <summary>Refuses startup until resolved or acknowledged.</summary>
    Blocking,

    /// <summary>
    /// A setting that is allowed but weaker than recommended. Logged at startup
    /// and shown to operators; never refuses startup.
    /// </summary>
    Advisory,
}

/// <summary>
/// A production posture condition. A blocking finding is safe only when it is
/// resolved or explicitly acknowledged for a bounded migration window; an
/// advisory finding is reported without blocking.
/// </summary>
public sealed record ProductionPostureFinding(
    string Id,
    string Summary,
    string Remedy,
    bool LegacyAcknowledged = false,
    ProductionPostureSeverity Severity = ProductionPostureSeverity.Blocking);

/// <summary>
/// The advisory posture findings of the running host that are not
/// acknowledged, for presentation to operators.
/// </summary>
public interface IProductionPostureAdvisories
{
    IReadOnlyList<ProductionPostureFinding> Evaluate();
}

/// <summary>
/// Contributes module-owned production posture findings to the composition
/// host. Feature modules own the knowledge of which of their options are
/// permissive; the host only aggregates and enforces the result.
/// </summary>
public interface IProductionPostureContributor
{
    IEnumerable<ProductionPostureFinding> Evaluate();
}

/// <summary>
/// A bounded, auditable exception for one stable posture finding ID.
/// </summary>
public sealed class ProductionPostureAcknowledgement
{
    public string Owner { get; init; } = string.Empty;

    public string Reason { get; init; } = string.Empty;

    public DateTimeOffset ExpiresAtUtc { get; init; }

    public bool IsValid(DateTimeOffset now) =>
        !string.IsNullOrWhiteSpace(Owner)
        && !string.IsNullOrWhiteSpace(Reason)
        && ExpiresAtUtc > now;
}
