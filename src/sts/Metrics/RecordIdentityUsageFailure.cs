using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Sufficit.Identity.STS.Metrics;

internal sealed class RecordAuthorizationUsageFailure(IIdentityUsageMetricSink sink)
    : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
            .UseSingletonHandler<RecordAuthorizationUsageFailure>()
            .SetOrder(int.MaxValue - 10_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
    {
        if (!string.IsNullOrWhiteSpace(context.Response.Error) &&
            !string.IsNullOrWhiteSpace(context.Request?.ClientId))
            sink.TryRecord(new(DateTime.UtcNow, context.Request.ClientId,
                "authorization_failed", "authorization", null,
                "failed", null));
        return ValueTask.CompletedTask;
    }
}

internal sealed class RecordTokenUsageFailure(IIdentityUsageMetricSink sink)
    : IOpenIddictServerHandler<ApplyTokenResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyTokenResponseContext>()
            .UseSingletonHandler<RecordTokenUsageFailure>()
            .SetOrder(int.MaxValue - 10_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ApplyTokenResponseContext context)
    {
        if (!string.IsNullOrWhiteSpace(context.Response.Error) &&
            !string.IsNullOrWhiteSpace(context.Request?.ClientId))
            sink.TryRecord(new(DateTime.UtcNow, context.Request.ClientId,
                "token_failed", "token", context.Request.GrantType,
                "failed", null));
        return ValueTask.CompletedTask;
    }
}
