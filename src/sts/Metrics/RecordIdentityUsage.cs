using System.Security.Cryptography;
using System.Text;
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

        var subject = context.Principal?.GetClaim(Claims.Subject);
        sink.TryRecord(new IdentityUsageMetric(
            DateTime.UtcNow,
            clientId,
            context.EndpointType.ToString().ToLowerInvariant() + "_issued",
            context.EndpointType.ToString().ToLowerInvariant(),
            context.Request?.GrantType,
            "succeeded",
            HashSubject(subject)));
        return ValueTask.CompletedTask;
    }

    private static string? HashSubject(string? subject) =>
        string.IsNullOrWhiteSpace(subject)
            ? null
            : Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(subject)))
                .ToLowerInvariant();
}
