using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Sufficit.Identity.STS.Metrics;

/// <summary>
/// Last-mile observer for successful OpenIddict sign-ins. TryRecord performs
/// no I/O and never waits, so telemetry cannot extend authentication latency.
/// </summary>
internal sealed class RecordIdentityUsage(IIdentityUsageMetricSink sink)
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
            .UseSingletonHandler<RecordIdentityUsage>()
            .SetOrder(AttachSignInParameters.Descriptor.Order + 2_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var clientId = context.Request?.ClientId;
        if (string.IsNullOrWhiteSpace(clientId)) return ValueTask.CompletedTask;

        sink.TryRecord(new IdentityUsageMetric(
            DateTime.UtcNow,
            clientId,
            context.EndpointType.ToString().ToLowerInvariant() + "_issued",
            context.EndpointType.ToString().ToLowerInvariant(),
            context.Request?.GrantType,
            "succeeded",
            UserOf(context, clientId)));
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// The subject when it is a user. A client-credentials token names the
    /// client itself, which is not a user.
    /// </summary>
    private static string? UserOf(ProcessSignInContext context, string clientId)
    {
        if (context.Request?.IsClientCredentialsGrantType() is true) return null;
        var subject = context.Principal?.GetClaim(Claims.Subject);
        return string.IsNullOrWhiteSpace(subject) || string.Equals(subject, clientId, StringComparison.Ordinal)
            ? null
            : subject;
    }
}
