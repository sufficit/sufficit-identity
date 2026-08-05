namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// A persisted SSF (Shared Signals Framework) event stream, RFC 8933. Each
/// stream is a logical subscription: a receiver configuration + the set of
/// subjects and events it wants, plus the delivery method (push RFC 8935 or
/// poll RFC 8934).
/// </summary>
public sealed class SsfStream
{
    /// <summary>Database primary key (GUID string).</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Opaque stream identifier shared with the client (the <c>stream_id</c>
    /// in RFC 8933 responses). Distinct from <see cref="Id"/> so the client
    /// never sees the database key directly.
    /// </summary>
    public string StreamId { get; set; } = string.Empty;

    /// <summary>Receiver audience (<c>aud</c> claim in emitted SETs).</summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Delivery method URN: <c>urn:ietf:rfc:8935</c> (push) or
    /// <c>urn:ietf:rfc:8934</c> (poll).
    /// </summary>
    public string DeliveryMethod { get; set; } = string.Empty;

    /// <summary>
    /// Push endpoint (HTTPS). Required for push delivery; null for poll.
    /// </summary>
    public string? Endpoint { get; set; }

    /// <summary>
    /// Optional Authorization header value for push delivery
    /// (e.g. <c>Bearer ...</c>). Configure from a secret source.
    /// </summary>
    public string? Authorization { get; set; }

    /// <summary>Stream lifecycle: <c>enabled</c>, <c>disabled</c>, <c>paused</c>.</summary>
    public string Status { get; set; } = "enabled";

    /// <summary>
    /// Transmitter-side verification state: <c>pending</c> until the receiver
    /// confirms it can decode the SETs (RFC 8933 §6).
    /// </summary>
    public string VerificationState { get; set; } = "pending";

    /// <summary>
    /// Subject scope: a JSON array of subject identifiers, or the literal
    /// <c>"ALL"</c> to receive events for every subject.
    /// </summary>
    public string SubjectScope { get; set; } = "ALL";

    /// <summary>
    /// JSON array of CAEP/SSF event-type URIs the stream requested. Empty
    /// array means "all events the transmitter supports".
    /// </summary>
    public string EventsRequested { get; set; } = "[]";

    /// <summary>Optional human-readable description.</summary>
    public string? Description { get; set; }

    public DateTime CreatedAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
}

/// <summary>
/// A queued SET awaiting poll delivery (RFC 8934). One row per SET per poll
/// stream. Push streams never produce rows here — they deliver inline.
/// </summary>
public sealed class SsfSetDelivery
{
    public long Id { get; set; }

    /// <summary>Foreign key to <see cref="SsfStream.StreamId"/>.</summary>
    public string StreamId { get; set; } = string.Empty;

    /// <summary>The SET's <c>jti</c> — for idempotent ack by the receiver.</summary>
    public string Jti { get; set; } = string.Empty;

    /// <summary>The complete signed SET (JWT compact serialization).</summary>
    public string SetPayload { get; set; } = string.Empty;

    public DateTime CreatedAtUtc { get; set; }

    /// <summary>
    /// When the receiver polled/acked the SET. Null = still pending delivery.
    /// </summary>
    public DateTime? ConsumedAt { get; set; }
}
