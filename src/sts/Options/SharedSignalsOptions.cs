using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// OpenID Shared Signals Framework 1.0 transmitter configuration. The first
/// production slice supports discovery plus RFC 8935 push delivery of signed
/// CAEP SETs to statically provisioned receivers. The optional dynamic stream
/// management API is intentionally not advertised.
/// </summary>
public sealed class SharedSignalsOptions
{
    /// <summary>Master switch. Default <c>false</c>.</summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// Statically provisioned push receivers. Secrets belong in environment
    /// variables or an external secret store, never committed appsettings.
    /// </summary>
    public List<SharedSignalsReceiverOptions> Receivers { get; init; } = new();

    /// <summary>
    /// Opt-in dynamic stream management API (RFC 8933). When true, exposes
    /// <c>/ssf/streams</c> for creating/reading/deleting streams and
    /// advertises <c>configuration_endpoint</c> in discovery. Default false —
    /// the REST surface is administrative and should be enabled deliberately.
    /// </summary>
    public bool StreamManagementEnabled { get; init; } = false;

    /// <summary>
    /// OAuth scope required to call the stream-management and poll endpoints.
    /// Default <c>ssf_transmitter</c>. The scope must exist as an OpenIddict
    /// scope (create it via the management API or provisioning manifest).
    /// </summary>
    public string RequiredScope { get; init; } = "ssf_transmitter";

    /// <summary>
    /// Requires MFA evidence for the dynamic stream-management and poll
    /// endpoints. These endpoints can subscribe to every subject and expose
    /// security events, so the sensitive transmitter scope is MFA-protected
    /// by default.
    /// </summary>
    public bool RequireMfa { get; init; } = true;

    /// <summary>
    /// Requires <c>subject</c> to be supplied explicitly when a stream is
    /// created, instead of defaulting to <c>ALL</c> (every subject in the
    /// deployment). Default <c>false</c> for compatibility: existing receivers
    /// legitimately rely on the <c>ALL</c> default, so tightening it is a
    /// breaking change an operator opts into. When false, an omitted subject
    /// still defaults to <c>ALL</c> but is logged at Warning.
    /// </summary>
    public bool RequireExplicitSubject { get; init; } = false;
}
public sealed class SharedSignalsReceiverOptions
{
    /// <summary>Stable operator-facing receiver identifier.</summary>
    public string Id { get; init; } = string.Empty;

    /// <summary>SET audience expected by this receiver.</summary>
    public string Audience { get; init; } = string.Empty;

    /// <summary>HTTPS RFC 8935 push endpoint.</summary>
    public string Endpoint { get; init; } = string.Empty;

    /// <summary>
    /// Optional value placed in the HTTP Authorization header, for example
    /// <c>Bearer ...</c>. Configure from a secret source.
    /// </summary>
    public string? Authorization { get; init; }
}
