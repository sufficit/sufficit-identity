using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS.SharedSignals;

/// <summary>
/// Adapter that turns the application-layer <see cref="ISecurityEventTrigger"/>
/// contract into <see cref="ISharedSignalsDispatcher"/> calls. This is the
/// single translation point between credential/device change events raised
/// anywhere in the STS / management / SCIM surfaces and the SSF transmitter.
/// </summary>
/// <remarks>
/// Delivery is best-effort: every method wraps the dispatcher call in a
/// bounded (8s) linked cancellation and swallows all exceptions, mirroring the
/// back-channel logout distribution contract. A receiver outage must never
/// undo an already-completed business operation; the dispatcher logs
/// observable delivery failures.
/// </remarks>
internal sealed class SharedSignalsSecurityEventTrigger : ISecurityEventTrigger
{
    private static readonly TimeSpan DeliveryTimeout = TimeSpan.FromSeconds(8);

    private readonly ISharedSignalsDispatcher _dispatcher;

    public SharedSignalsSecurityEventTrigger(ISharedSignalsDispatcher dispatcher)
    {
        _dispatcher = dispatcher;
    }

    public Task CredentialChangedAsync(
        string subject,
        string? sessionId,
        CaepCredentialChange change,
        CancellationToken cancellationToken = default) =>
        DispatchAsync(
            ct => _dispatcher.CredentialChangedAsync(subject, sessionId, change, ct),
            cancellationToken);

    public Task DeviceChangedAsync(
        string subject,
        string? sessionId,
        CaepDeviceChange change,
        CancellationToken cancellationToken = default) =>
        DispatchAsync(
            ct => _dispatcher.DeviceChangedAsync(subject, sessionId, change, ct),
            cancellationToken);

    public Task AssuranceLevelChangedAsync(
        string subject,
        string? sessionId,
        CaepAssuranceLevelChange change,
        CancellationToken cancellationToken = default) =>
        DispatchAsync(
            ct => _dispatcher.AssuranceLevelChangedAsync(subject, sessionId, change, ct),
            cancellationToken);

    private static async Task DispatchAsync(
        Func<CancellationToken, Task> dispatch,
        CancellationToken cancellationToken)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(DeliveryTimeout);
            await dispatch(timeout.Token);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The caller's own token cancelled; surface that as usual.
            throw;
        }
        catch (Exception)
        {
            // Best-effort delivery: a receiver outage must not propagate.
        }
    }
}

/// <summary>
/// No-op <see cref="ISecurityEventTrigger"/> registered when SSF is disabled,
/// so every account/management/SCIM service can take the dependency
/// unconditionally.
/// </summary>
internal sealed class NullSecurityEventTrigger : ISecurityEventTrigger
{
    public Task CredentialChangedAsync(
        string subject,
        string? sessionId,
        CaepCredentialChange change,
        CancellationToken cancellationToken = default) => Task.CompletedTask;

    public Task DeviceChangedAsync(
        string subject,
        string? sessionId,
        CaepDeviceChange change,
        CancellationToken cancellationToken = default) => Task.CompletedTask;

    public Task AssuranceLevelChangedAsync(
        string subject,
        string? sessionId,
        CaepAssuranceLevelChange change,
        CancellationToken cancellationToken = default) => Task.CompletedTask;
}
