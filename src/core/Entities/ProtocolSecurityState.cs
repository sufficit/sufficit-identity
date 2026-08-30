namespace Sufficit.Identity.Core.Entities;

public sealed class DpopReplayEntry
{
    public string Key { get; set; } = string.Empty;
    public DateTime ExpiresAtUtc { get; set; }
}

/// <summary>
/// Durable, expiring key/value state for protocol features whose data has no
/// table of its own: DPoP nonce challenges, front-channel logout context and
/// passkey ceremony tickets.
/// </summary>
/// <remarks>
/// These three used to live only in <c>IDistributedCache</c>, which defaults to
/// process-local memory — so a replicated deployment silently lost nonce
/// challenges, logout fan-out and in-flight passkey ceremonies across replicas
/// (eval 2026-08-30, F-4). Giving them a database primary mirrors what CIBA and
/// the DPoP replay cache already do.
/// <para>One table rather than three: the shape is identical in all three cases
/// (opaque key, opaque payload, expiry), and <see cref="Purpose"/> keeps the
/// namespaces apart for cleanup and diagnostics. <see cref="Payload"/> is bytes
/// so it can hold a protected passkey ticket as naturally as a UTF-8
/// string.</para>
/// </remarks>
public sealed class ProtocolStateEntry
{
    /// <summary>Hash of purpose + caller key; never the raw key.</summary>
    public string Key { get; set; } = string.Empty;

    /// <summary>Feature namespace, for cleanup and diagnostics only.</summary>
    public string Purpose { get; set; } = string.Empty;

    public byte[] Payload { get; set; } = [];

    public DateTime ExpiresAtUtc { get; set; }
}

public sealed class CibaPendingState
{
    public string AuthReqId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string ScopesJson { get; set; } = "[]";
    public string? BindingMessage { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime LastPollAtUtc { get; set; }
    public string? ApprovedSubject { get; set; }
    public string State { get; set; } = "pending";
    public string? ConsumptionId { get; set; }
}
