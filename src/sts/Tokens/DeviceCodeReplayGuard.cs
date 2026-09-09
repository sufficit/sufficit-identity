using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Sufficit.Identity.STS.Tokens;

/// <summary>
/// Rejects a REPLAYED (already redeemed) device_code at the token endpoint
/// WITHOUT the revocation cascade OpenIddict's built-in
/// <see cref="Protection.ValidateTokenEntry"/> would otherwise trigger.
/// </summary>
/// <para>
/// Why this exists (issue #61, CI run 34357932338). RFC 8628 clients poll
/// <c>/connect/token</c> on a timer, and one final poll can still be in
/// flight when approval completes, so two polls routinely race for the SAME
/// single-use device_code. Exactly one wins. What the loser does depends on
/// interleaving:
///
///  * Loser's <c>ProcessAuthentication</c> runs BEFORE the winner commits:
///    <c>Protection.RedeemTokenEntry</c> loses the <c>TryRedeemAsync</c> race
///    and rejects with <c>invalid_token</c>/ID2011 — no side effects. The
///    winner's tokens keep working.
///  * Loser's <c>ProcessAuthentication</c> runs AFTER the winner committed:
///    the built-in <c>Protection.ValidateTokenEntry</c> sees a REDEEMED entry
///    and interprets it as token THEFT (the same heuristic that guards
///    refresh-token rotation) — it calls
///    <c>RevokeByAuthorizationIdAsync</c>, revoking EVERY token of the
///    authorization, including the reference access/refresh tokens just
///    issued to the winner. The winner's next <c>/connect/userinfo</c> then
///    returns 401. This was the intermittent CI failure: same race, different
///    arrival order, test outcome flipped.
/// </para>
/// <para>
/// For device codes that theft heuristic is wrong: the authorization was
/// created seconds ago for this exact client, subject and scopes, and the
/// replaying caller presented the same client credentials that were used to
/// redeem it. A device_code replay is a protocol error the polling client is
/// EXPECTED to make (timer vs. approval race), not evidence a token was
/// stolen — so the correct response is <c>invalid_grant</c> and nothing else.
/// Refresh-token replay is NOT touched: that flow keeps OpenIddict's native
/// theft response (reuse of a rotated refresh token remains a revocation
/// event, exactly as before).
/// </para>
internal sealed class RejectRedeemedDeviceCodeReplay(
    IOpenIddictTokenManager tokenManager) : IOpenIddictServerHandler<ValidateTokenContext>
{
    // Literals mirrored from OpenIddict's own built-in handlers (which match
    // on these exact strings): TokenTypeIdentifiers has no DeviceCode member
    // exposed for this comparison and token statuses are plain strings in
    // IOpenIddictTokenManager calls.
    private const string DeviceCodeTokenType =
        "urn:openiddict:params:oauth:token-type:device_code";
    private const string RedeemedStatus = "redeemed";

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
            .UseScopedHandler<RejectRedeemedDeviceCodeReplay>()
            .SetOrder(
                Protection.ValidateTokenEntry.Descriptor.Order - 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidateTokenContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Only the device_code grant's token validation is in scope; every
        // other token type (access, refresh, authorization code, user code)
        // must keep the built-in semantics untouched.
        if (context.Principal?.GetTokenType() is not DeviceCodeTokenType)
        {
            return;
        }

        // No stored entry to inspect (degraded mode / token storage off /
        // self-contained token without an id): defer to the built-ins.
        if (string.IsNullOrEmpty(context.TokenId))
        {
            return;
        }

        var entry = await tokenManager.FindByIdAsync(context.TokenId);
        if (entry is null || !await tokenManager.HasStatusAsync(
                entry, RedeemedStatus))
        {
            // Not a replay (still valid, pending or rejected): let the
            // built-in handlers produce authorization_pending / access_denied
            // / expiry exactly as before.
            return;
        }

        // The device_code was already redeemed by the winner of the race.
        // Reject the replay outright so the dispatcher stops BEFORE
        // Protection.ValidateTokenEntry's theft branch can revoke the
        // authorization — the winner's freshly issued tokens stay valid.
        context.Reject(
            error: Errors.InvalidGrant,
            description: "The device code has already been redeemed.");
    }
}
