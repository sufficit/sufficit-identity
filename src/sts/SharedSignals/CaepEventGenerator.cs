using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS.SharedSignals;

/// <summary>Generates explicitly typed, signed SSF/CAEP Security Event Tokens.</summary>
public sealed class CaepEventGenerator
{
    public const string SecurityEventTokenType = "secevent+jwt";
    public const string SessionRevokedEventType =
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
    public const string CredentialChangeEventType =
        "https://schemas.openid.net/secevent/caep/event-type/credential-change";
    public const string DeviceChangeEventType =
        "https://schemas.openid.net/secevent/caep/event-type/device-change";
    public const string AssuranceLevelChangeEventType =
        "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";
    public const string VerificationEventType =
        "https://schemas.openid.net/secevent/risc/event-type/verification";

    private readonly JsonWebTokenHandler _handler = new()
    {
        // SSF forbids exp. IdentityModel otherwise injects a default exp when
        // the descriptor intentionally leaves it unset.
        SetDefaultTimesOnTokenCreation = false,
    };
    private readonly SigningCredentials _signingCredentials;
    private readonly string _issuer;
    private readonly TimeProvider _timeProvider;

    public CaepEventGenerator(
        SigningCredentials signingCredentials,
        string issuer,
        TimeProvider? timeProvider = null)
    {
        _signingCredentials = signingCredentials ??
            throw new ArgumentNullException(nameof(signingCredentials));
        _issuer = string.IsNullOrWhiteSpace(issuer)
            ? throw new ArgumentException("Issuer is required.", nameof(issuer))
            : new Uri(issuer, UriKind.Absolute).AbsoluteUri;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public string GenerateSessionRevoked(
        string subject,
        string? sessionId,
        string audience,
        string? transactionId = null) =>
        CreateSet(
            audience,
            BuildSubjectIdentifier(subject, sessionId),
            transactionId,
            events: new Dictionary<string, object>
            {
                [SessionRevokedEventType] = new Dictionary<string, object>
                {
                    ["event_timestamp"] = _timeProvider.GetUtcNow().ToUnixTimeSeconds(),
                },
            });

    /// <summary>
    /// Generates a CAEP <c>credential-change</c> SET (CAEP 1.0 §3.3.1). The
    /// payload carries <c>change_type</c> and <c>credential_type</c>, plus the
    /// optional <c>federated_type</c> for federated credentials.
    /// </summary>
    public string GenerateCredentialChange(
        string subject,
        string? sessionId,
        string audience,
        CaepCredentialChange change,
        string? transactionId = null)
    {
        ArgumentNullException.ThrowIfNull(change);
        return CreateSet(
            audience,
            BuildSubjectIdentifier(subject, sessionId),
            transactionId,
            events: new Dictionary<string, object>
            {
                [CredentialChangeEventType] = BuildCredentialChangePayload(change),
            });
    }

    /// <summary>
    /// Generates a CAEP <c>device-change</c> SET (CAEP 1.0 §3.3.2). Used for
    /// device-bound credentials (WebAuthn / FIDO2 passkeys).
    /// </summary>
    public string GenerateDeviceChange(
        string subject,
        string? sessionId,
        string audience,
        CaepDeviceChange change,
        string? transactionId = null)
    {
        ArgumentNullException.ThrowIfNull(change);
        return CreateSet(
            audience,
            BuildSubjectIdentifier(subject, sessionId),
            transactionId,
            events: new Dictionary<string, object>
            {
                [DeviceChangeEventType] = BuildDeviceChangePayload(change),
            });
    }

    // -----------------------------------------------------------------------
    // CaepSubjectIdentifier overloads — used by stream-managed delivery where
    // the subject can be any RFC 8933 format (email, phone, device, jwt-id,
    // uri, complex). The legacy (subject, sessionId) overloads above remain
    // for the static-receiver / account-trigger paths.
    // -----------------------------------------------------------------------

    public string GenerateSessionRevoked(
        CaepSubjectIdentifier subject,
        string audience,
        string? transactionId = null) =>
        CreateSet(
            audience,
            MaterializeSubjectIdentifier(subject),
            transactionId,
            events: new Dictionary<string, object>
            {
                [SessionRevokedEventType] = new Dictionary<string, object>
                {
                    ["event_timestamp"] = _timeProvider.GetUtcNow().ToUnixTimeSeconds(),
                },
            });

    public string GenerateCredentialChange(
        CaepSubjectIdentifier subject,
        string audience,
        CaepCredentialChange change,
        string? transactionId = null)
    {
        ArgumentNullException.ThrowIfNull(change);
        return CreateSet(
            audience,
            MaterializeSubjectIdentifier(subject),
            transactionId,
            events: new Dictionary<string, object>
            {
                [CredentialChangeEventType] = BuildCredentialChangePayload(change),
            });
    }

    public string GenerateDeviceChange(
        CaepSubjectIdentifier subject,
        string audience,
        CaepDeviceChange change,
        string? transactionId = null)
    {
        ArgumentNullException.ThrowIfNull(change);
        return CreateSet(
            audience,
            MaterializeSubjectIdentifier(subject),
            transactionId,
            events: new Dictionary<string, object>
            {
                [DeviceChangeEventType] = BuildDeviceChangePayload(change),
            });
    }

    private Dictionary<string, object> BuildCredentialChangePayload(CaepCredentialChange change)
    {
        var payload = new Dictionary<string, object>
        {
            ["event_timestamp"] = _timeProvider.GetUtcNow().ToUnixTimeSeconds(),
            ["change_type"] = ToChangeTypeString(change.Operation),
            ["credential_type"] = ToCredentialTypeString(change.CredentialType),
        };
        if (change.CredentialType == CaepCredentialType.Federated
            && !string.IsNullOrWhiteSpace(change.FederatedType))
        {
            payload["federated_type"] = change.FederatedType;
        }
        return payload;
    }

    private Dictionary<string, object> BuildDeviceChangePayload(CaepDeviceChange change)
    {
        var payload = new Dictionary<string, object>
        {
            ["event_timestamp"] = _timeProvider.GetUtcNow().ToUnixTimeSeconds(),
            ["change_type"] = ToChangeTypeString(change.Operation),
        };
        if (!string.IsNullOrWhiteSpace(change.CredentialId))
        {
            payload["credential_id"] = change.CredentialId;
        }
        if (!string.IsNullOrWhiteSpace(change.Description))
        {
            payload["description"] = change.Description;
        }
        return payload;
    }

    // -----------------------------------------------------------------------
    // assurance-level-change (CAEP 1.0 §3.3.4)
    // -----------------------------------------------------------------------

    public string GenerateAssuranceLevelChange(
        string subject,
        string? sessionId,
        string audience,
        CaepAssuranceLevelChange change,
        string? transactionId = null) =>
        GenerateAssuranceLevelChange(
            sessionId is null
                ? CaepSubjectIdentifier.IssSub(subject)
                : CaepSubjectIdentifier.Complex(
                    CaepSubjectIdentifier.IssSub(subject),
                    CaepSubjectIdentifier.Opaque(sessionId)),
            audience,
            change,
            transactionId);

    public string GenerateAssuranceLevelChange(
        CaepSubjectIdentifier subject,
        string audience,
        CaepAssuranceLevelChange change,
        string? transactionId = null)
    {
        ArgumentNullException.ThrowIfNull(change);
        return CreateSet(
            audience,
            MaterializeSubjectIdentifier(subject),
            transactionId,
            events: new Dictionary<string, object>
            {
                [AssuranceLevelChangeEventType] = BuildAssuranceLevelChangePayload(change),
            });
    }

    private Dictionary<string, object> BuildAssuranceLevelChangePayload(
        CaepAssuranceLevelChange change)
    {
        var payload = new Dictionary<string, object>
        {
            ["event_timestamp"] = _timeProvider.GetUtcNow().ToUnixTimeSeconds(),
            ["current_level"] = ToAssuranceLevelString(change.CurrentLevel),
        };

        if (change.PreviousLevel is { } previous)
        {
            payload["previous_level"] = ToAssuranceLevelString(previous);
        }

        // LOA (level-of-assurance) is the more granular cousin of `level`.
        // Default the LOA fields from the level when not explicitly supplied.
        var currentLoa = change.CurrentLoa ?? change.CurrentLevel;
        payload["current_loa"] = ToLoaString(currentLoa);

        var previousLoa = change.PreviousLoa ?? change.PreviousLevel;
        if (previousLoa is { } loa)
        {
            payload["previous_loa"] = ToLoaString(loa);
        }

        return payload;
    }

    // -----------------------------------------------------------------------
    // verification (SSF §11 / RFC 8933 stream-creation handshake)
    // -----------------------------------------------------------------------

    /// <summary>
    /// Generates an SSF <c>verification</c> SET emitted when a stream is
    /// created. The receiver must echo the opaque <paramref name="state"/>
    /// back to the verification endpoint to confirm it can decode SETs.
    /// </summary>
    public string GenerateVerification(
        string audience,
        string state,
        string? transactionId = null) =>
        CreateSet(
            audience,
            // Verification SETs are addressed to the receiver itself (no
            // specific subject). RFC 8933 §4: the subject is optional for
            // this event type.
            new Dictionary<string, object>
            {
                ["format"] = "opaque",
                ["id"] = "stream-verification",
            },
            transactionId,
            events: new Dictionary<string, object>
            {
                [VerificationEventType] = new Dictionary<string, object>
                {
                    ["event_timestamp"] = _timeProvider.GetUtcNow().ToUnixTimeSeconds(),
                    ["state"] = state,
                },
            });

    /// <summary>
    /// Shared SET construction: assembles <c>jti</c>, <c>txn</c>,
    /// <c>sub_id</c> and the supplied <paramref name="events"/> map, then
    /// signs the token with the STS auxiliary signing credentials. SSF forbids
    /// both <c>sub</c> and <c>exp</c> on the SET profile; neither is emitted.
    /// </summary>
    private string CreateSet(
        string audience,
        object subjectIdentifier,
        string? transactionId,
        IReadOnlyDictionary<string, object> events)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);

        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N"),
            ["txn"] = string.IsNullOrWhiteSpace(transactionId)
                ? Guid.NewGuid().ToString("N")
                : transactionId,
            ["sub_id"] = subjectIdentifier,
            ["events"] = events,
        };

        return _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = audience,
            IssuedAt = _timeProvider.GetUtcNow().UtcDateTime,
            SigningCredentials = _signingCredentials,
            TokenType = SecurityEventTokenType,
            Claims = claims,
        });
    }

    /// <summary>
    /// Builds the CAEP subject identifier. With a <paramref name="sessionId"/>
    /// it produces the <c>complex</c> form (iss_sub user + opaque session);
    /// without one it produces the plain <c>iss_sub</c> form used by
    /// administrative / provisioning events.
    /// </summary>
    private object BuildSubjectIdentifier(string subject, string? sessionId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);

        if (string.IsNullOrWhiteSpace(sessionId))
        {
            return new Dictionary<string, object>
            {
                ["format"] = "iss_sub",
                ["iss"] = _issuer,
                ["sub"] = subject,
            };
        }

        return new Dictionary<string, object>
        {
            ["format"] = "complex",
            ["user"] = new Dictionary<string, object>
            {
                ["format"] = "iss_sub",
                ["iss"] = _issuer,
                ["sub"] = subject,
            },
            ["session"] = new Dictionary<string, object>
            {
                ["format"] = "opaque",
                ["id"] = sessionId,
            },
        };
    }

    /// <summary>
    /// Materializes a <see cref="CaepSubjectIdentifier"/> for SET emission:
    /// fills in any <c>null</c> <c>iss</c> with this transmitter's issuer and
    /// returns the JSON-serializable <c>sub_id</c> object. Stream-managed
    /// receivers can supply subjects in any RFC 8933 format; this is the single
    /// place that normalizes them before signing.
    /// </summary>
    private object MaterializeSubjectIdentifier(CaepSubjectIdentifier subject)
    {
        ArgumentNullException.ThrowIfNull(subject);
        return FillIssuer(subject.Value);

        // Recursively walks the sub_id object replacing null `iss` entries with
        // the transmitter's issuer (RFC 8933: iss is REQUIRED; callers may omit
        // it and let the transmitter supply its own).
        object FillIssuer(object node) => node switch
        {
            Dictionary<string, object?> dict => dict.ToDictionary(
                kv => kv.Key,
                kv => kv.Key == "iss" && kv.Value is null
                    ? _issuer
                    : kv.Value is null ? null : FillIssuer(kv.Value),
                StringComparer.Ordinal),
            _ => node,
        };
    }

    private static string ToChangeTypeString(CaepChangeOperation operation) => operation switch
    {
        CaepChangeOperation.Created => "create",
        CaepChangeOperation.Updated => "update",
        CaepChangeOperation.Deleted => "delete",
        _ => throw new ArgumentOutOfRangeException(nameof(operation), operation, "Unknown change operation."),
    };

    private static string ToCredentialTypeString(CaepCredentialType type) => type switch
    {
        CaepCredentialType.Password => "password",
        CaepCredentialType.Otp => "otp",
        CaepCredentialType.Federated => "federated",
        CaepCredentialType.Passkey => "passkey",
        // Not a CAEP-defined credential_type; emitted as a Sufficit-local
        // value so receivers can react to privilege/authority changes.
        CaepCredentialType.Privilege => "urn:sufficit:credential-type:privilege",
        _ => throw new ArgumentOutOfRangeException(nameof(type), type, "Unknown credential type."),
    };

    private static string ToAssuranceLevelString(CaepAssuranceLevel level) => level switch
    {
        CaepAssuranceLevel.Loa1 => "normal",
        CaepAssuranceLevel.Loa2 => "loa2",
        CaepAssuranceLevel.Loa3 => "loa3",
        CaepAssuranceLevel.PhishingResistant => "phishing-resistant",
        _ => throw new ArgumentOutOfRangeException(nameof(level), level, "Unknown assurance level."),
    };

    private static string ToLoaString(CaepAssuranceLevel level) => level switch
    {
        CaepAssuranceLevel.Loa1 => "loa1",
        CaepAssuranceLevel.Loa2 => "loa2",
        CaepAssuranceLevel.Loa3 => "loa3",
        // No numeric LOA for phishing-resistant; the spec uses the symbolic name.
        CaepAssuranceLevel.PhishingResistant => "phishing-resistant",
        _ => throw new ArgumentOutOfRangeException(nameof(level), level, "Unknown assurance level."),
    };
}
