using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Sufficit.Identity.Core.Services;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Sufficit.Identity.STS.Security;

/// <summary>
/// Refuses a disabled client (plan E1) on every endpoint that names one —
/// authorization, PAR, device authorization, token (every grant, refresh
/// included) and introspection — and refuses any token it was issued, so its
/// access tokens stop working at userinfo and introspect as inactive. The
/// check is a lookup in <see cref="IDisabledClientRegistry"/>'s in-memory set.
/// </summary>
internal sealed class RejectDisabledClient(IDisabledClientRegistry registry, ILogger<RejectDisabledClient> logger) :
    IOpenIddictServerHandler<ValidateAuthorizationRequestContext>,
    IOpenIddictServerHandler<ValidatePushedAuthorizationRequestContext>,
    IOpenIddictServerHandler<ValidateDeviceAuthorizationRequestContext>,
    IOpenIddictServerHandler<ValidateTokenRequestContext>,
    IOpenIddictServerHandler<ValidateIntrospectionRequestContext>,
    IOpenIddictServerHandler<ValidateTokenContext>
{
    internal const string Description = "The client application is disabled.";
    private const int RequestOrder = int.MinValue + 60_000;

    public static IEnumerable<OpenIddictServerHandlerDescriptor> Descriptors { get; } =
    [
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseSingletonHandler<RejectDisabledClient>().SetOrder(RequestOrder)
            .SetType(OpenIddictServerHandlerType.Custom).Build(),
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidatePushedAuthorizationRequestContext>()
            .UseSingletonHandler<RejectDisabledClient>().SetOrder(RequestOrder)
            .SetType(OpenIddictServerHandlerType.Custom).Build(),
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateDeviceAuthorizationRequestContext>()
            .UseSingletonHandler<RejectDisabledClient>().SetOrder(RequestOrder)
            .SetType(OpenIddictServerHandlerType.Custom).Build(),
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
            .UseSingletonHandler<RejectDisabledClient>().SetOrder(RequestOrder)
            .SetType(OpenIddictServerHandlerType.Custom).Build(),
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateIntrospectionRequestContext>()
            .UseSingletonHandler<RejectDisabledClient>().SetOrder(RequestOrder)
            .SetType(OpenIddictServerHandlerType.Custom).Build(),
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
            .UseSingletonHandler<RejectDisabledClient>()
            .SetOrder(Protection.ValidateTokenEntry.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom).Build(),
    ];

    public ValueTask HandleAsync(ValidateAuthorizationRequestContext context) =>
        Reject(context, context.ClientId, OpenIddictConstants.Errors.UnauthorizedClient);

    public ValueTask HandleAsync(ValidatePushedAuthorizationRequestContext context) =>
        Reject(context, context.ClientId, OpenIddictConstants.Errors.UnauthorizedClient);

    public ValueTask HandleAsync(ValidateDeviceAuthorizationRequestContext context) =>
        Reject(context, context.ClientId, OpenIddictConstants.Errors.UnauthorizedClient);

    public ValueTask HandleAsync(ValidateTokenRequestContext context) =>
        Reject(context, context.ClientId, OpenIddictConstants.Errors.UnauthorizedClient);

    public ValueTask HandleAsync(ValidateIntrospectionRequestContext context) =>
        Reject(context, context.ClientId, OpenIddictConstants.Errors.UnauthorizedClient);

    /// <summary>A token presented by anyone: refused when any client it was issued to is disabled.</summary>
    public ValueTask HandleAsync(ValidateTokenContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.IsRejected || context.Principal is null)
            return ValueTask.CompletedTask;
        foreach (var presenter in context.Principal.GetPresenters())
        {
            if (registry.IsDisabled(presenter))
            {
                logger.LogInformation("Token of disabled client {ClientId} refused.", presenter);
                context.Reject(OpenIddictConstants.Errors.InvalidToken, Description);
                break;
            }
        }
        return ValueTask.CompletedTask;
    }

    private ValueTask Reject(BaseValidatingContext context, string? clientId, string error)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (registry.IsDisabled(clientId))
        {
            logger.LogInformation("Disabled client {ClientId} refused at {Endpoint}.", clientId, context.EndpointType);
            context.Reject(error, Description);
        }
        return ValueTask.CompletedTask;
    }
}
