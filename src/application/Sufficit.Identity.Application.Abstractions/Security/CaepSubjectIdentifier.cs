namespace Sufficit.Identity.Application.Security;

/// <summary>
/// A CAEP / SSF subject identifier (RFC 8933 §2.2 "Subject Identifier Formats").
/// Carries the fully-formed <c>sub_id</c> object that the SSF transmitter embeds
/// in a SET. Factory methods cover every format defined by the spec; the issuer
/// (<c>iss</c>) is left null when omitted and filled in by the transmitter at
/// SET-generation time.
/// </summary>
/// <remarks>
/// The <see cref="Value"/> is an opaque <see cref="object"/> (a dictionary shape)
/// so this contract stays free of JSON-schema dependencies. Callers should use
/// the static factory methods rather than constructing it directly.
/// </remarks>
public sealed record CaepSubjectIdentifier(object Value)
{
    /// <summary>
    /// <c>iss_sub</c> format — identifies a subject by issuer + subject id pair.
    /// This is the default for the existing account/management/SCIM triggers.
    /// </summary>
    public static CaepSubjectIdentifier IssSub(string subject, string? issuer = null) =>
        new(new Dictionary<string, object?>
        {
            ["format"] = "iss_sub",
            ["iss"] = issuer,
            ["sub"] = subject,
        });

    /// <summary>
    /// <c>email</c> format — identifies a subject by verified email address.
    /// </summary>
    public static CaepSubjectIdentifier Email(string email, string? issuer = null) =>
        new(new Dictionary<string, object?>
        {
            ["format"] = "email",
            ["iss"] = issuer,
            ["email"] = email,
        });

    /// <summary>
    /// <c>phone</c> format — identifies a subject by verified phone number
    /// (E.164).
    /// </summary>
    public static CaepSubjectIdentifier Phone(string phone, string? issuer = null) =>
        new(new Dictionary<string, object?>
        {
            ["format"] = "phone",
            ["iss"] = issuer,
            ["phone"] = phone,
        });

    /// <summary>
    /// <c>device</c> format — identifies a device bound to a subject
    /// (e.g. a WebAuthn credential). <c>device_id</c> is the device-bound
    /// credential id; <c>sub</c> is the owning subject.
    /// </summary>
    public static CaepSubjectIdentifier Device(
        string subject,
        string deviceId,
        string? issuer = null) =>
        new(new Dictionary<string, object?>
        {
            ["format"] = "device",
            ["iss"] = issuer,
            ["sub"] = subject,
            ["device_id"] = deviceId,
        });

    /// <summary>
    /// <c>jwt-id</c> format — identifies a JWT by its <c>jti</c> + <c>iss</c>.
    /// Useful for session-revoked events that target a single token id.
    /// </summary>
    public static CaepSubjectIdentifier JwtId(string jti, string issuer) =>
        new(new Dictionary<string, object?>
        {
            ["format"] = "jwt-id",
            ["iss"] = issuer,
            ["jti"] = jti,
        });

    /// <summary>
    /// <c>uri</c> format — identifies a subject by an arbitrary absolute URI.
    /// </summary>
    public static CaepSubjectIdentifier Uri(string uri) =>
        new(new Dictionary<string, object?>
        {
            ["format"] = "uri",
            ["uri"] = uri,
        });

    /// <summary>
    /// <c>opaque</c> format — an opaque, transmitter-local identifier (e.g. an
    /// internal session id). Used as the inner session identifier of the
    /// <see cref="Complex"/> form.
    /// </summary>
    public static CaepSubjectIdentifier Opaque(string id) =>
        new(new Dictionary<string, object?>
        {
            ["format"] = "opaque",
            ["id"] = id,
        });

    /// <summary>
    /// <c>complex</c> format — composes a <c>user</c> subject identifier (any
    /// single-subject format, typically <see cref="IssSub"/>) with a
    /// <c>session</c> subject identifier (typically <see cref="Opaque"/>) so a
    /// single SET can address both the user and a specific session.
    /// </summary>
    public static CaepSubjectIdentifier Complex(
        CaepSubjectIdentifier user,
        CaepSubjectIdentifier session)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(session);
        return new CaepSubjectIdentifier(new Dictionary<string, object?>
        {
            ["format"] = "complex",
            ["user"] = user.Value,
            ["session"] = session.Value,
        });
    }
}
