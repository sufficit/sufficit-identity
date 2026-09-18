using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using NATS.Client;
using Sufficit.Identity.Core.Sessions;

namespace Sufficit.Identity.Server;

internal sealed class UserSecurityNatsOptions
{
    public bool Enabled { get; set; }
    public string Url { get; set; } = "nats://127.0.0.1:4222";
    public string? Token { get; set; }
    public string? Subject { get; set; }
}

/// <summary>
/// Tells the other nodes that a user's sessions must be revalidated, and
/// applies what they say to the local cache.
/// </summary>
/// <remarks>
/// Deliberately the same shape as <see cref="TrustedProxyNatsBridge"/>: a
/// best-effort notification next to an authoritative database. Nothing here
/// grants access — a message can only ever cause one more read of the security
/// stamp, never one less — so a malformed or hostile payload costs a lookup and
/// nothing else. That is also why the session cache only skips reads while this
/// bridge reports a connected channel.
/// </remarks>
internal sealed class UserSecurityNatsBridge : BackgroundService, IUserSecurityChangePublisher
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private static readonly Regex SubjectPattern =
        new(@"^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+$", RegexOptions.Compiled);
    private static readonly Regex UserIdPattern =
        new(@"^[a-zA-Z0-9._@:-]{1,128}$", RegexOptions.Compiled);

    private readonly UserSecurityNatsOptions options;
    private readonly ISessionValidityCache cache;
    private readonly ILogger<UserSecurityNatsBridge> logger;
    private readonly string subject;
    private readonly string origin = $"{Environment.MachineName}-{Guid.NewGuid():N}";
    private IConnection? connection;

    public bool Enabled => options.Enabled;

    public bool Connected => Volatile.Read(ref connection)?.State == ConnState.CONNECTED;

    public UserSecurityNatsBridge(
        IOptions<UserSecurityNatsOptions> options,
        ISessionValidityCache cache,
        IHostEnvironment environment,
        ILogger<UserSecurityNatsBridge> logger)
    {
        this.options = options.Value;
        this.cache = cache;
        this.logger = logger;
        subject = this.options.Subject
            ?? $"sufficit.{environment.EnvironmentName.ToLowerInvariant()}.identity.user-security.changed.v1";
        if (Enabled && (!SubjectPattern.IsMatch(subject)
            || !Uri.TryCreate(this.options.Url, UriKind.Absolute, out var uri)
            || uri.Scheme is not ("nats" or "tls")))
        {
            throw new ArgumentException("Invalid user security NATS subject or URL.");
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!Enabled)
        {
            return;
        }

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
                using var subscription = candidate.SubscribeAsync(
                    subject,
                    (_, args) => Receive(args.Message.Data));
                candidate.Flush(1000);
                Volatile.Write(ref connection, candidate);
                logger.LogInformation("User security notifications connected.");
                while (candidate.State == ConnState.CONNECTED && !stoppingToken.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                // Never log URLs or exceptions that can carry broker credentials.
                logger.LogWarning(
                    "User security notifications unavailable ({ErrorType}); sessions fall back to reading the security stamp.",
                    exception.GetType().Name);
            }
            finally
            {
                if (Interlocked.Exchange(ref connection, null) is not null)
                {
                    logger.LogInformation("User security notifications disconnected.");
                }
            }

            try
            {
                await Task.Delay(
                    TimeSpan.FromSeconds(2 + Random.Shared.NextDouble()),
                    stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    internal void Receive(byte[] payload)
    {
        if (payload.Length > 2048)
        {
            return;
        }

        try
        {
            var message = JsonSerializer.Deserialize<UserSecurityChanged>(payload, Json);
            if (message is null || message.SchemaVersion != 1 || message.EventId == Guid.Empty
                || message.Domain != "user-security"
                || string.IsNullOrWhiteSpace(message.OriginInstance)
                || message.OriginInstance.Length > 256
                || message.OriginInstance == origin
                || message.UserId is null
                || !UserIdPattern.IsMatch(message.UserId))
            {
                return;
            }

            cache.Invalidate(message.UserId);
        }
        catch (JsonException)
        {
            // A malformed notification cannot grant anything; it is dropped.
        }
    }

    public Task<bool> PublishAsync(string userId, CancellationToken cancellationToken)
    {
        var active = Volatile.Read(ref connection);
        if (cancellationToken.IsCancellationRequested
            || active?.State != ConnState.CONNECTED
            || string.IsNullOrEmpty(userId)
            || !UserIdPattern.IsMatch(userId))
        {
            return Task.FromResult(false);
        }

        try
        {
            var message = new UserSecurityChanged(
                1,
                Guid.NewGuid(),
                origin,
                "user-security",
                userId,
                DateTimeOffset.UtcNow);
            active.Publish(subject, JsonSerializer.SerializeToUtf8Bytes(message, Json));
            // Accepted by the transport, NOT an acknowledgement that peers applied it.
            return Task.FromResult(true);
        }
        catch (NATSException)
        {
            return Task.FromResult(false);
        }
        catch (ObjectDisposedException)
        {
            return Task.FromResult(false);
        }
    }

    internal sealed record UserSecurityChanged(
        int SchemaVersion,
        Guid EventId,
        string OriginInstance,
        string Domain,
        string UserId,
        DateTimeOffset OccurredAt);
}
