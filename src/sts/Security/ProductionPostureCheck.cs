using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS.Security;

/// <summary>
/// Aggregates module-owned production posture findings, applies only bounded
/// acknowledgements and refuses non-Development startup while any unresolved
/// finding remains.
/// </summary>
public static class ProductionPostureCheck
{
    public static IReadOnlyList<ProductionPostureFinding> Evaluate(
        IEnumerable<IProductionPostureContributor> contributors,
        SecurityPostureOptions options,
        DateTimeOffset now,
        ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(contributors);
        ArgumentNullException.ThrowIfNull(options);

        var raw = contributors
            .SelectMany(contributor => contributor.Evaluate())
            .ToArray();
        var duplicate = raw
            .GroupBy(finding => finding.Id, StringComparer.Ordinal)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicate is not null)
        {
            throw new InvalidOperationException(
                $"Production posture finding ID '{duplicate.Key}' is registered more than once.");
        }

        var findingsById = raw.ToDictionary(
            finding => finding.Id,
            StringComparer.Ordinal);
        var unresolved = new List<ProductionPostureFinding>();

        foreach (var finding in raw)
        {
            if (options.Acknowledgements.TryGetValue(
                    finding.Id,
                    out var acknowledgement))
            {
                if (acknowledgement.IsValid(now))
                {
                    logger?.LogWarning(
                        "Security posture finding [{FindingId}] is temporarily acknowledged by {Owner} until {ExpiresAtUtc}: {Reason}",
                        finding.Id,
                        acknowledgement.Owner,
                        acknowledgement.ExpiresAtUtc,
                        acknowledgement.Reason);
                    continue;
                }

                logger?.LogError(
                    "Security posture acknowledgement for [{FindingId}] is invalid or expired; owner, reason and a future ExpiresAtUtc are required.",
                    finding.Id);
            }

            if (finding.LegacyAcknowledged
                && options.AllowLegacyBooleanAcknowledgements)
            {
                logger?.LogWarning(
                    "Security posture finding [{FindingId}] is suppressed by a deprecated boolean acknowledgement. Replace it with Security:Acknowledgements metadata before disabling AllowLegacyBooleanAcknowledgements.",
                    finding.Id);
                continue;
            }

            unresolved.Add(finding);
        }

        foreach (var acknowledgement in options.Acknowledgements)
        {
            if (!findingsById.ContainsKey(acknowledgement.Key))
            {
                unresolved.Add(new ProductionPostureFinding(
                    $"stale-acknowledgement:{acknowledgement.Key}",
                    $"A production posture acknowledgement exists for inactive or unknown finding '{acknowledgement.Key}'.",
                    "Remove stale Security:Acknowledgements entries; acknowledgements must not outlive their findings."));
            }
        }

        return unresolved;
    }

    public static void Enforce(
        IServiceProvider services,
        SufficitIdentityOptions options,
        bool isDevelopment,
        ILogger logger,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        IReadOnlyList<ProductionPostureFinding> findings;
        using (var scope = services.CreateScope())
        {
            var contributors = scope.ServiceProvider
                .GetServices<IProductionPostureContributor>();
            findings = Evaluate(
                contributors,
                options.Security,
                (timeProvider ?? TimeProvider.System).GetUtcNow(),
                logger);
        }

        if (findings.Count == 0)
        {
            logger.LogInformation(
                "Production posture check passed: no unresolved permissive security settings are active.");
            return;
        }

        if (isDevelopment)
        {
            foreach (var finding in findings)
            {
                logger.LogWarning(
                    "Development security posture finding [{FindingId}]: {Summary} Remedy: {Remedy}",
                    finding.Id,
                    finding.Summary,
                    finding.Remedy);
            }

            return;
        }

        var detail = string.Join(
            Environment.NewLine,
            findings.Select(finding =>
                $"  - [{finding.Id}] {finding.Summary} Remedy: {finding.Remedy}"));
        throw new ProductionPostureException(
            findings,
            "Refusing to start: the production security posture check found "
            + $"{findings.Count} unresolved finding(s):"
            + Environment.NewLine
            + detail
            + Environment.NewLine
            + "Resolve each finding or configure a bounded Security:Acknowledgements entry with owner, reason and expiry.");
    }
}

public sealed class ProductionPostureException(
    IReadOnlyList<ProductionPostureFinding> findings,
    string message) : Exception(message)
{
    public IReadOnlyList<ProductionPostureFinding> Findings { get; } = findings;
}
