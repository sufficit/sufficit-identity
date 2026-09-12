using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS;

/// <summary>
/// An external assertion held aside until control of its email address is
/// proven.
/// </summary>
/// <remarks>
/// No return URL is carried. The proof is redeemed from the mailbox, commonly
/// in another browser or device than the one that started the flow, so resuming
/// an authorization request that no longer exists there would fail anyway — and
/// a redirect target that survives a message is one more thing to validate.
/// </remarks>
public sealed record PendingExternalIdentity(
    string Provider,
    string ProviderKey,
    string? ProviderDisplayName,
    string Email,
    string? PictureUrl);

/// <summary>
/// Holds an unproven external identity between the provider callback and the
/// moment the address is proven.
/// </summary>
/// <remarks>
/// <para>
/// Nothing is written to the user store while a link is pending. That is the
/// whole point: an account that exists is an account an attacker can keep a
/// binding on, so the binding may not precede the proof.
/// </para>
/// <para>
/// State lives in <see cref="IProtocolStateStore"/> — the same durable,
/// expiring store the DPoP nonces and the front-channel logout context use —
/// rather than in a protected cookie, so that redemption is single-use and
/// survives across replicas. A cookie could be replayed by whoever holds it;
/// consuming a row cannot.
/// </para>
/// </remarks>
public sealed class PendingExternalIdentityStore
{
    private readonly IProtocolStateStore _state;

    /// <summary>
    /// Internal because the state store it depends on is an implementation
    /// detail of this assembly; the type itself is public so the sign-in
    /// service, which is public, can take it as a dependency.
    /// </summary>
    internal PendingExternalIdentityStore(IProtocolStateStore state) =>
        _state = state;

    private const string Purpose = "external-identity-link";

    /// <summary>256 bits. The ticket authorizes creating an account bound to an
    /// external identity, so it is sized as a credential, not as an id.</summary>
    private const int TicketBytes = 32;

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    /// <summary>
    /// Persists a pending link and returns the single-use ticket that redeems
    /// it. The ticket is the only thing that travels to the address being
    /// proven.
    /// </summary>
    public async Task<string> CreateAsync(
        PendingExternalIdentity pending,
        TimeSpan lifetime,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pending);

        var ticket = WebEncoders.Base64UrlEncode(
            RandomNumberGenerator.GetBytes(TicketBytes));
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            pending,
            SerializerOptions);
        await _state.SetAsync(
            Purpose,
            TicketKey(ticket),
            payload,
            lifetime,
            cancellationToken);
        return ticket;
    }

    /// <summary>
    /// Redeems a ticket, removing it first so a replay finds nothing even if
    /// the caller fails midway. A link that was consumed but not completed is
    /// recoverable by starting the provider flow again; a link that could be
    /// consumed twice is not recoverable at all.
    /// </summary>
    public async Task<PendingExternalIdentity?> RedeemAsync(
        string? ticket,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(ticket))
        {
            return null;
        }

        var key = TicketKey(ticket);
        var payload = await _state.GetAsync(Purpose, key, cancellationToken);
        await _state.RemoveAsync(Purpose, key, cancellationToken);
        if (payload is null || payload.Length == 0)
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<PendingExternalIdentity>(
                payload,
                SerializerOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Clamps the configured window. Read here rather than at startup so a
    /// value edited in place cannot widen the window beyond a day.
    /// </summary>
    public static TimeSpan ResolveLifetime(ExternalIdentityOptions options) =>
        TimeSpan.FromMinutes(
            Math.Clamp(options.VerificationLifetimeMinutes, 5, 1440));

    /// <summary>
    /// The stored key is a hash of the ticket, so a database reader cannot
    /// redeem a pending link — the same reason a session token is not stored
    /// verbatim.
    /// </summary>
    private static string TicketKey(string ticket) =>
        Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(ticket)));
}
