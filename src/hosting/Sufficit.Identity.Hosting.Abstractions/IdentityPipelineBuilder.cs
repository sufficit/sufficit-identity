using Microsoft.AspNetCore.Builder;

namespace Sufficit.Identity.Hosting;

/// <summary>
/// Fixed stages of the identity request pipeline, in execution order. The
/// numeric gaps leave room for new stages without renumbering.
/// </summary>
public enum IdentityPipelineStage
{
    /// <summary>Client certificate and forwarded-header resolution; nothing may read the client address or scheme before it.</summary>
    Forwarding = 100,

    /// <summary>HSTS and HTTPS redirection.</summary>
    TransportSecurity = 200,

    SecurityHeaders = 300,

    Localization = 400,

    PathCanonicalization = 500,

    Routing = 600,

    /// <summary>After routing, so endpoint rate-limit policies are visible.</summary>
    RateLimiting = 700,

    /// <summary>Before authentication, so preflight requests get policy headers.</summary>
    Cors = 800,

    /// <summary>Middleware that must observe requests before authentication, such as documentation or status pages.</summary>
    PreAuthentication = 900,

    Authentication = 1000,

    Authorization = 1100,

    PostAuthorization = 1200,

    Endpoints = 1300,
}

/// <summary>A registered pipeline contribution, as recorded by <see cref="IdentityPipelineBuilder"/>.</summary>
public sealed record IdentityPipelineStep(
    IdentityPipelineStage Stage,
    string Name,
    string Owner);

/// <summary>
/// Collects pipeline contributions from the host and its modules and applies
/// them ordered by stage, keeping registration order within a stage.
/// </summary>
public sealed class IdentityPipelineBuilder
{
    private readonly List<(IdentityPipelineStep Step, int Sequence, Action<IApplicationBuilder> Configure)> _contributions = [];
    private readonly HashSet<string> _applied = new(StringComparer.Ordinal);

    /// <summary>Owner recorded for subsequent contributions; the catalog sets it to each module id.</summary>
    public string Owner { get; set; } = "host";

    public IdentityPipelineBuilder Use(
        IdentityPipelineStage stage,
        string name,
        Action<IApplicationBuilder> configure)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(configure);
        if (!Enum.IsDefined(stage))
        {
            throw new ArgumentOutOfRangeException(nameof(stage), stage, "Unknown pipeline stage.");
        }

        if (_contributions.Any(entry => string.Equals(entry.Step.Name, name, StringComparison.Ordinal)))
        {
            throw new InvalidOperationException(
                $"The pipeline step '{name}' is already registered.");
        }

        _contributions.Add((new IdentityPipelineStep(stage, name, Owner), _contributions.Count, configure));
        return this;
    }

    /// <summary>
    /// Registers endpoint mapping that needs the full <see cref="WebApplication"/>
    /// (Razor components, static assets, branches) at the endpoints stage.
    /// </summary>
    public IdentityPipelineBuilder MapEndpoints(
        string name,
        Action<WebApplication> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        return Use(IdentityPipelineStage.Endpoints, name, app =>
            configure(app as WebApplication
                ?? throw new InvalidOperationException(
                    $"The pipeline step '{name}' requires a WebApplication host.")));
    }

    /// <summary>Contributions in the order they will be applied.</summary>
    public IReadOnlyList<IdentityPipelineStep> Steps =>
        Ordered().Select(entry => entry.Step).ToArray();

    public void Apply(IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        foreach (var entry in Ordered())
        {
            ApplyEntry(app, entry.Step, entry.Configure);
        }
    }

    /// <summary>
    /// Applies only the contributions of one stage, for a host whose own
    /// pipeline has not moved into the builder yet. Pair it with
    /// <see cref="EnsureAllApplied"/> so a contribution at another stage fails
    /// startup instead of silently running at the wrong position.
    /// </summary>
    public void ApplyStage(IApplicationBuilder app, IdentityPipelineStage stage)
    {
        ArgumentNullException.ThrowIfNull(app);
        foreach (var entry in Ordered().Where(entry => entry.Step.Stage == stage))
        {
            ApplyEntry(app, entry.Step, entry.Configure);
        }
    }

    public void EnsureAllApplied()
    {
        var pending = _contributions
            .Where(entry => !_applied.Contains(entry.Step.Name))
            .Select(entry => $"{entry.Step.Name} ({entry.Step.Stage}, {entry.Step.Owner})")
            .ToArray();
        if (pending.Length > 0)
        {
            throw new InvalidOperationException(
                "Pipeline contributions were registered at stages the host does not apply: "
                + string.Join(", ", pending) + ".");
        }
    }

    private void ApplyEntry(
        IApplicationBuilder app,
        IdentityPipelineStep step,
        Action<IApplicationBuilder> configure)
    {
        if (!_applied.Add(step.Name))
        {
            throw new InvalidOperationException(
                $"The pipeline step '{step.Name}' was already applied.");
        }

        configure(app);
    }

    private IEnumerable<(IdentityPipelineStep Step, int Sequence, Action<IApplicationBuilder> Configure)> Ordered() =>
        _contributions
            .OrderBy(entry => entry.Step.Stage)
            .ThenBy(entry => entry.Sequence);
}
