using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using NATS.Client;
using Sufficit.Identity.Core.Networking;

namespace Sufficit.Identity.Server;

internal sealed class TrustedProxyNatsOptions
{
    public bool Enabled { get; set; }
    public string Url { get; set; } = "nats://127.0.0.1:4222";
    public string? Token { get; set; }
    public string? Subject { get; set; }
}

internal sealed record TrustedProxyChanged(int SchemaVersion, Guid EventId, string OriginInstance,
    string Domain, string Scope, string Revision, DateTimeOffset OccurredAtUtc);

/// <summary>Optional notification transport. No database access or authoritative payloads.</summary>
internal sealed class TrustedProxyNatsBridge : BackgroundService, ITrustedProxyChangePublisher
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly TrustedProxyNatsOptions options;
    private readonly TrustedProxyRefreshSignal signal;
    private readonly ILogger<TrustedProxyNatsBridge> logger;
    private readonly string subject;
    private readonly string origin = $"{Environment.MachineName}-{Guid.NewGuid():N}";
    private IConnection? connection;
    public bool Enabled => options.Enabled;
    public bool Connected => Volatile.Read(ref connection)?.State == ConnState.CONNECTED;

    public TrustedProxyNatsBridge(IOptions<TrustedProxyNatsOptions> options,
        TrustedProxyRefreshSignal signal, IHostEnvironment environment, ILogger<TrustedProxyNatsBridge> logger)
    {
        this.options = options.Value;
        this.signal = signal;
        this.logger = logger;
        subject = this.options.Subject ?? $"sufficit.{environment.EnvironmentName.ToLowerInvariant()}.identity.trusted-proxies.changed.v1";
        if (Enabled && (!Regex.IsMatch(subject, @"^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+$")
            || !Uri.TryCreate(this.options.Url, UriKind.Absolute, out var uri)
            || uri.Scheme is not ("nats" or "tls")))
            throw new ArgumentException("Invalid trusted proxy NATS subject or URL.");
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!Enabled) return;
        // Own initial AND subsequent reconnect attempts, instead of giving up on startup failure.
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var settings = ConnectionFactory.GetDefaultOptions();
                settings.Url = options.Url;
                settings.Token = options.Token;
                settings.Name = origin;
                settings.Timeout = 1000;
                settings.AllowReconnect = false;
                using var candidate = new ConnectionFactory().CreateConnection(settings);
                using var subscription = candidate.SubscribeAsync(subject, (_, args) => Receive(args.Message.Data));
                candidate.Flush(1000); // Subscription registered before requesting reconciliation.
                Volatile.Write(ref connection, candidate);
                signal.Request();
                logger.LogInformation("Trusted proxy notifications connected.");
                while (candidate.State == ConnState.CONNECTED && !stoppingToken.IsCancellationRequested)
                    await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            {
                // Do not log URLs/options/exceptions that can contain broker credentials.
                logger.LogWarning("Trusted proxy notifications unavailable ({ErrorType}); revision reconciliation remains active.",
                    exception.GetType().Name);
            }
            finally
            {
                if (Interlocked.Exchange(ref connection, null) is not null)
                    logger.LogInformation("Trusted proxy notifications disconnected.");
            }
            try { await Task.Delay(TimeSpan.FromSeconds(2 + Random.Shared.NextDouble()), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }

    internal void Receive(byte[] payload)
    {
        if (payload.Length > 2048) return;
        try
        {
            var message = JsonSerializer.Deserialize<TrustedProxyChanged>(payload, Json);
            if (message is null || message.SchemaVersion != 1 || message.EventId == Guid.Empty
                || message.Domain != "trusted-proxies" || message.Scope != "global"
                || string.IsNullOrWhiteSpace(message.OriginInstance) || message.OriginInstance.Length > 256
                || message.OriginInstance == origin || message.Revision is null
                || !Regex.IsMatch(message.Revision, "^[a-fA-F0-9]{32}$")) return;
            signal.Request(message.Revision);
        }
        catch (JsonException) { /* Malformed notifications cannot change configuration. */ }
    }

    public Task<bool> PublishAsync(string revision, CancellationToken cancellationToken)
    {
        var active = Volatile.Read(ref connection);
        if (cancellationToken.IsCancellationRequested || active?.State != ConnState.CONNECTED) return Task.FromResult(false);
        try
        {
            var message = new TrustedProxyChanged(1, Guid.NewGuid(), origin, "trusted-proxies", "global", revision, DateTimeOffset.UtcNow);
            active.Publish(subject, JsonSerializer.SerializeToUtf8Bytes(message, Json));
            // Accepted by the client transport, NOT an acknowledgement that peers applied it.
            return Task.FromResult(true);
        }
        catch (NATSException) { return Task.FromResult(false); }
        catch (ObjectDisposedException) { return Task.FromResult(false); }
    }
}
