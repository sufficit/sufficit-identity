namespace Sufficit.Identity.Application.Security;

/// <summary>
/// A production posture condition that is safe only when it is resolved or
/// explicitly acknowledged for a bounded migration window.
/// </summary>
public sealed record ProductionPostureFinding(
    string Id,
    string Summary,
    string Remedy,
    bool LegacyAcknowledged = false);

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
