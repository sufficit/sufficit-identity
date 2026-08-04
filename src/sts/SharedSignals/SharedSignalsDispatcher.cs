using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;

namespace Sufficit.Identity.STS.SharedSignals;

public interface ISharedSignalsDispatcher
{
    Task SessionRevokedAsync(
        string subject,
        string? sessionId,
        CancellationToken cancellationToken);
}

internal sealed class SharedSignalsPushDispatcher : ISharedSignalsDispatcher
{
    private readonly CaepEventGenerator _generator;
    private readonly SharedSignalsOptions _options;
    private readonly HttpClient _httpClient;
    private readonly ILogger<SharedSignalsPushDispatcher> _logger;

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

    public Task SessionRevokedAsync(
        string subject,
        string? sessionId,
        CancellationToken cancellationToken) =>
        Task.WhenAll(_options.Receivers.Select(receiver =>
            DeliverAsync(receiver, subject, sessionId, cancellationToken)));

    private async Task DeliverAsync(
        SharedSignalsReceiverOptions receiver,
        string subject,
        string? sessionId,
        CancellationToken cancellationToken)
    {
        var token = _generator.GenerateSessionRevoked(
            subject, sessionId, receiver.Audience);

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
                        "SSF/CAEP session-revoked delivered to receiver {ReceiverId}.",
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
}
