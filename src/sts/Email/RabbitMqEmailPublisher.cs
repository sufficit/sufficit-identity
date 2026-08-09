using System.Text.Json;
using System.Text.Json.Serialization;
using System.Security.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;

namespace Sufficit.Identity.STS.Email;

internal sealed class RabbitMqEmailOptions
{
    public const string SectionName = "Sufficit:Exchange:RabbitMQ";

    public bool Persistent { get; init; } = true;
    public string HostName { get; init; } = string.Empty;
    public string UserName { get; init; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public TimeSpan? Heartbeat { get; init; }
    public int Port { get; init; }
    public bool UseTls { get; init; } = false;
    public bool RequireTls { get; init; } = false;
    public string? TlsServerName { get; init; }
    public bool CheckCertificateRevocation { get; init; } = true;
}

internal sealed class EmailQueueMessage
{
    [JsonPropertyOrder(0)]
    [JsonPropertyName("type")]
    public string Type => "EMAIL";

    [JsonPropertyOrder(0)]
    [JsonPropertyName("id")]
    public Guid Id { get; init; }

    [JsonPropertyOrder(0)]
    [JsonPropertyName("recipient")]
    public string Recipient { get; init; } = string.Empty;

    [JsonPropertyOrder(1)]
    [JsonPropertyName("modelid")]
    public Guid ModelId { get; init; }

    [JsonPropertyOrder(2)]
    [JsonPropertyName("body")]
    public byte[] Body { get; init; } = [];

    [JsonPropertyName("subject")]
    public string Subject { get; init; } = string.Empty;

    [JsonPropertyName("trackable")]
    public bool Trackable { get; init; } = true;
}

internal interface IEmailMessagePublisher
{
    Task PublishAsync(EmailQueueMessage message, CancellationToken cancellationToken);
}

/// <summary>
/// Minimal, Identity-owned publisher for the established Q-EMAIL contract.
/// Keeping this transport local avoids pulling the complete
/// Sufficit.Communication/EFData/Pomelo graph into the EF Core 10 STS.
/// </summary>
internal sealed class RabbitMqEmailPublisher : IEmailMessagePublisher, IAsyncDisposable
{
    private const string QueueName = "Q-EMAIL";

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private readonly RabbitMqEmailOptions _options;
    private readonly ILogger<RabbitMqEmailPublisher> _logger;
    private readonly SemaphoreSlim _connectionGate = new(1, 1);
    private IConnection? _connection;

    public RabbitMqEmailPublisher(
        IOptions<RabbitMqEmailOptions> options,
        ILogger<RabbitMqEmailPublisher> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public async Task PublishAsync(EmailQueueMessage message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);

        var connection = await GetConnectionAsync(cancellationToken);
        using var channel = await connection.CreateChannelAsync(cancellationToken: cancellationToken);

        // Preserve the legacy publisher's fail-fast behavior: Q-EMAIL is an
        // operationally managed durable queue and must already exist.
        await channel.QueueDeclarePassiveAsync(QueueName, cancellationToken);

        var properties = new BasicProperties
        {
            ContentType = "application/json"
        };
        var payload = Serialize(message);

        await channel.BasicPublishAsync(
            exchange: string.Empty,
            routingKey: QueueName,
            mandatory: true,
            basicProperties: properties,
            body: payload,
            cancellationToken: cancellationToken);
    }

    internal static byte[] Serialize(EmailQueueMessage message) =>
        JsonSerializer.SerializeToUtf8Bytes(message, SerializerOptions);

    private async Task<IConnection> GetConnectionAsync(CancellationToken cancellationToken)
    {
        if (_connection is { IsOpen: true })
            return _connection;

        await _connectionGate.WaitAsync(cancellationToken);
        try
        {
            if (_connection is { IsOpen: true })
                return _connection;

            if (_connection is not null)
                await _connection.DisposeAsync();

            var factory = new ConnectionFactory
            {
                HostName = FirstHost(_options.HostName),
                Port = EffectivePort,
                UserName = _options.UserName,
                Password = _options.Password,
                AutomaticRecoveryEnabled = _options.Persistent,
                ClientProvidedName = $"{Environment.MachineName.ToLowerInvariant()}:sufficit-identity",
                Ssl = BuildSslOptions(),
            };

            if (_options.Heartbeat is { } heartbeat)
                factory.RequestedHeartbeat = heartbeat;

            var endpoints = _options.HostName
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(host => new AmqpTcpEndpoint(
                    host,
                    EffectivePort,
                    BuildSslOptions(host)))
                .ToArray();

            _connection = endpoints.Length > 1
                ? await factory.CreateConnectionAsync(endpoints, cancellationToken)
                : await factory.CreateConnectionAsync(cancellationToken);

            _logger.LogInformation(
                "connected to RabbitMQ for Q-EMAIL via {Host}",
                _connection.Endpoint?.HostName ?? FirstHost(_options.HostName));

            return _connection;
        }
        finally
        {
            _connectionGate.Release();
        }
    }

    private static string FirstHost(string hosts) =>
        hosts.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault()
        ?? throw new InvalidOperationException("RabbitMQ HostName is required.");

    private int EffectivePort => _options.Port > 0
        ? _options.Port
        : _options.UseTls ? 5671 : 5672;

    private SslOption BuildSslOptions(string? host = null) => new()
    {
        Enabled = _options.UseTls,
        ServerName = string.IsNullOrWhiteSpace(_options.TlsServerName)
            ? host ?? FirstHost(_options.HostName)
            : _options.TlsServerName,
        Version = SslProtocols.Tls12 | SslProtocols.Tls13,
        CheckCertificateRevocation = _options.CheckCertificateRevocation,
    };

    public async ValueTask DisposeAsync()
    {
        if (_connection is not null)
            await _connection.DisposeAsync();

        _connectionGate.Dispose();
    }
}
