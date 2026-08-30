using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// DPoP (RFC 9449) — sender-constrains access tokens to a client-provided key,
/// neutralizing token theft/replay without requiring mTLS. A client sends a
/// short-lived signed <c>DPoP</c> proof header with each token request; the STS
/// validates it and embeds the proof key's thumbprint (<c>cnf.jkt</c>) in the
/// issued access token, so resource servers can reject the token when a later
/// request does not present a matching proof (item 3.1).
/// </summary>
/// <remarks>
/// <b>Implemented from scratch</b> — OpenIddict 7.6 has no DPoP support
/// (verified: zero "dpop" strings in any assembly). The proof validator
/// (<c>Dpop.DpopProofValidator</c>) and the <c>cnf</c> attachment live in the
/// STS controller, not in OpenIddict handlers, to stay portable for a future
/// move off OpenIddict. Opt-in by default: when disabled, the STS behaves
/// exactly as before (pure bearer tokens).
/// <para>
/// When <see cref="Enabled"/> is true but <see cref="RequireForAllClients"/> is
/// false (the default), DPoP is ACCEPTED-but-not-required: clients that send a
/// valid proof get a sender-constrained token; clients that don't get a plain
/// bearer token (backward compatible). Flip <see cref="RequireForAllClients"/>
/// to reject bearer entirely — only do this once every client is DPoP-capable.
/// </para>
/// </remarks>
public sealed class DpopOptions
{
    /// <summary>
    /// Master switch. When <c>true</c>, the STS validates the <c>DPoP</c>
    /// header on token requests and sender-constrains tokens whose requests
    /// carried a valid proof. Default <c>false</c>.
    /// </summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// When <c>true</c>, a valid DPoP proof is REQUIRED on every token request
    /// — requests without one (or with an invalid one) are rejected. Default
    /// <c>false</c> (accept-but-don't-require) so legacy bearer clients keep
    /// working during a gradual rollout. Flip only after confirming every
    /// client sends DPoP proofs.
    /// </summary>
    public bool RequireForAllClients { get; init; } = false;

    /// <summary>
    /// When <c>true</c>, the AS enforces the DPoP nonce dance (RFC 9449 §8):
    /// a proof without a valid <c>nonce</c> claim is rejected with HTTP 400
    /// <c>use_dpop_nonce</c> and a <c>DPoP-Nonce</c> response header; the
    /// client retries carrying that nonce. RECOMMENDED by the RFC (bounds
    /// pre-computation attacks) but not required. Default <c>false</c> — flip
    /// to harden once clients implement the retry. Ignored when
    /// <see cref="Enabled"/> is false.
    /// </summary>
    public bool RequireNonce { get; init; } = false;
}
