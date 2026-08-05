using System.Net.Http.Headers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS.SharedSignals;

public interface ISharedSignalsDispatcher
{
    Task SessionRevokedAsync(
        string subject,
        string? sessionId,
        CancellationToken cancellationToken);

    Task CredentialChangedAsync(
        string subject,
        string? sessionId,
        CaepCredentialChange change,
        CancellationToken cancellationToken);

    Task DeviceChangedAsync(
        string subject,
        string? sessionId,
        CaepDeviceChange change,
        CancellationToken cancellationToken);

    Task AssuranceLevelChangedAsync(
        string subject,
        string? sessionId,
        CaepAssuranceLevelChange change,
        CancellationToken cancellationToken);
}

internal sealed class SharedSignalsPushDispatcher : ISharedSignalsDispatcher
{
    private readonly CaepEventGenerator _generator;
    private readonly SharedSignalsOptions _options;
    private readonly HttpClient _httpClient;
    private readonly ILogger<SharedSignalsPushDispatcher> _logger;
    private readonly IServiceScopeFactory? _scopeFactory;

    public SharedSignalsPushDispatcher(
        CaepEventGenerator generator,
        SharedSignalsOptions options,
        HttpClient httpClient,
        ILogger<SharedSignalsPushDispatcher> logger)
    {
        _generator = generator;
        _options = options;
        _httpClient = httpClient;
        _logger = logger;
    }

    /// <summary>
    /// Optional scope factory for stream-managed delivery (RFC 8933/8934).
    /// Injected by DI when available; null when stream management is off.
    /// </summary>
    [Microsoft.Extensions.DependencyInjection.ActivatorUtilitiesConstructor]
    public SharedSignalsPushDispatcher(
        CaepEventGenerator generator,
        SharedSignalsOptions options,
        HttpClient httpClient,
        ILogger<SharedSignalsPushDispatcher> logger,
        IServiceScopeFactory scopeFactory)
        : this(generator, options, httpClient, logger)
    {
        _scopeFactory = scopeFactory;
    }

    public Task SessionRevokedAsync(
        string subject,
        string? sessionId,
        CancellationToken cancellationToken) =>
        FanOutAsync(
            cancellationToken,
            audience => _generator.GenerateSessionRevoked(subject, sessionId, audience));

    public Task CredentialChangedAsync(
        string subject,
        string? sessionId,
        CaepCredentialChange change,
        CancellationToken cancellationToken) =>
        FanOutAsync(
            cancellationToken,
            audience => _generator.GenerateCredentialChange(subject, sessionId, audience, change));

    public Task DeviceChangedAsync(
        string subject,
        string? sessionId,
        CaepDeviceChange change,
        CancellationToken cancellationToken) =>
        FanOutAsync(
            cancellationToken,
            audience => _generator.GenerateDeviceChange(subject, sessionId, audience, change));

    public Task AssuranceLevelChangedAsync(
        string subject,
        string? sessionId,
        CaepAssuranceLevelChange change,
        CancellationToken cancellationToken) =>
        FanOutAsync(
            cancellationToken,
            audience => _generator.GenerateAssuranceLevelChange(subject, sessionId, audience, change));

    /// <summary>
    /// Delivers a per-receiver-generated SET to every configured receiver in
    /// parallel. The <paramref name="generateForAudience"/> factory produces a
    /// fresh signed SET per receiver so each carries the correct <c>aud</c>.
    /// Stream-managed receivers (RFC 8933) are also covered when the optional
    /// <see cref="ISsfStreamStore"/> is available: push streams receive inline
    /// HTTP delivery, poll streams are enqueued for later pull (RFC 8934).
    /// </summary>
    private async Task FanOutAsync(
        CancellationToken cancellationToken,
        Func<string, string> generateForAudience)
    {
        var staticTasks = _options.Receivers.Select(receiver =>
            DeliverAsync(receiver, generateForAudience, cancellationToken));

        var streamTask = (_scopeFactory is null)
            ? Task.CompletedTask
            : DeliverToStreamsAsync(generateForAudience, cancellationToken);

        await Task.WhenAll(staticTasks.Append(streamTask));
    }

    /// <summary>
    /// Delivers SETs to RFC 8933 streams persisted in the store. Push streams
    /// use the same HTTP path as static receivers; poll streams are enqueued.
    /// </summary>
    private async Task DeliverToStreamsAsync(
        Func<string, string> generateForAudience,
        CancellationToken cancellationToken)
    {
        if (_scopeFactory is null) return;

        using var scope = _scopeFactory.CreateScope();
        var store = scope.ServiceProvider.GetService<ISsfStreamStore>();
        if (store is null) return;

        // Push streams: deliver via HTTP using their configured endpoint/auth.
        var pushStreams = await store.ListEnabledPushAsync(cancellationToken);
        var pushTasks = pushStreams.Select(stream => DeliverPushStreamAsync(
            stream, generateForAudience(stream.Audience), cancellationToken));
        await Task.WhenAll(pushTasks);

        // Poll streams: persist the SET for later pull.
        var pollStreams = await store.ListEnabledPollAsync(cancellationToken);
        foreach (var stream in pollStreams)
        {
            var set = generateForAudience(stream.Audience);
            // jti extraction: read the SET's jti for idempotent enqueue. Fall
            // back to a fresh GUID if the SET can't be parsed (defensive).
            var jti = ExtractJti(set) ?? Guid.NewGuid().ToString("N");
            try
            {
                await store.EnqueuePollDeliveryAsync(stream.StreamId, jti, set, cancellationToken);
            }
            catch (Exception exception)
            {
                _logger.LogWarning(exception,
                    "SSF/CAEP poll enqueue to stream {StreamId} failed.",
                    stream.StreamId);
            }
        }
    }

    private async Task DeliverPushStreamAsync(
        Core.Entities.SsfStream stream,
        string set,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(stream.Endpoint)) return;

        var receiver = new SharedSignalsReceiverOptions
        {
            Id = stream.StreamId,
            Audience = stream.Audience,
            Endpoint = stream.Endpoint!,
            Authorization = stream.Authorization,
        };
        // generateForAudience already produced the SET for this audience, so
        // bypass regeneration by wrapping in a constant factory.
        await DeliverAsync(receiver, _ => set, cancellationToken);
    }

    private static string? ExtractJti(string set)
    {
        try
        {
            var jwt = new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(set);
            return jwt.TryGetPayloadValue("jti", out string jti) ? jti : null;
        }
        catch
        {
            return null;
        }
    }

    private async Task DeliverAsync(
        SharedSignalsReceiverOptions receiver,
        Func<string, string> generateForAudience,
        CancellationToken cancellationToken)
    {
        var token = generateForAudience(receiver.Audience);

        const int maxAttempts = 3;
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, receiver.Endpoint);
                request.Content = new StringContent(token);
                request.Content.Headers.ContentType =
                    new MediaTypeHeaderValue("application/secevent+jwt");
                if (!string.IsNullOrWhiteSpace(receiver.Authorization))
                {
                    request.Headers.TryAddWithoutValidation(
                        "Authorization", receiver.Authorization);
                }

                using var response = await _httpClient.SendAsync(
                    request, cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation(
                        "SSF/CAEP SET delivered to receiver {ReceiverId}.",
                        receiver.Id);
                    return;
                }

                if ((int)response.StatusCode is >= 400 and < 500)
                {
                    _logger.LogWarning(
                        "SSF/CAEP receiver {ReceiverId} rejected the SET with status {Status}; not retrying.",
                        receiver.Id, (int)response.StatusCode);
                    return;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (attempt < maxAttempts)
            {
                _logger.LogWarning(exception,
                    "SSF/CAEP delivery to {ReceiverId} failed on attempt {Attempt}; retrying.",
                    receiver.Id, attempt);
            }

            if (attempt < maxAttempts)
                await Task.Delay(TimeSpan.FromMilliseconds(250 * attempt), cancellationToken);
        }

        _logger.LogWarning(
            "SSF/CAEP delivery to receiver {ReceiverId} exhausted retries.",
            receiver.Id);
    }
}

internal sealed class NullSharedSignalsDispatcher : ISharedSignalsDispatcher
{
    public Task SessionRevokedAsync(
        string subject,
        string? sessionId,
        CancellationToken cancellationToken) => Task.CompletedTask;

    public Task CredentialChangedAsync(
        string subject,
        string? sessionId,
        CaepCredentialChange change,
        CancellationToken cancellationToken) => Task.CompletedTask;

    public Task DeviceChangedAsync(
        string subject,
        string? sessionId,
        CaepDeviceChange change,
        CancellationToken cancellationToken) => Task.CompletedTask;

    public Task AssuranceLevelChangedAsync(
        string subject,
        string? sessionId,
        CaepAssuranceLevelChange change,
        CancellationToken cancellationToken) => Task.CompletedTask;
}
