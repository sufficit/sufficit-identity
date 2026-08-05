using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Sufficit.Identity.STS.Dpop;

/// <summary>
/// Validates a DPoP proof JWT (RFC 9449) and extracts the binding material for
/// sender-constraining the issued access token.
/// </summary>
/// <remarks>
/// OpenIddict 7.6 has NO DPoP support (verified: zero "dpop" strings in any
/// assembly). This class implements the resource-server-independent proof
/// VALIDATION half of RFC 9449 §4.2-§4.3: it parses the client-supplied DPoP
/// header, verifies the signature against the embedded JWK, checks the htm/htu
/// claims match the request, enforces the typ=dpop+jwt header, and rejects
/// replay via a jti cache + optional nonce. The resulting
/// <see cref="DpopProof"/> carries the <c>cnf.jkt</c> thumbprint the token
/// endpoint attaches to the access token (§7.2). Portable: depends only on
/// <c>Microsoft.IdentityModel.JsonWebTokens</c>/<c>Tokens</c> — not on OpenIddict
/// internals — so it survives a future move off OpenIddict.
/// </remarks>
public sealed class DpopProofValidator
{
    /// <summary>The JWT typ header value for a DPoP proof (RFC 9449 §4.2).</summary>
    public const string DpopHeaderType = "dpop+jwt";

    /// <summary>The <c>typ</c> for an access-token-bound DPoP confirmation (RFC 9449 §7.2).</summary>
    public const string ConfirmationClaimType = "cnf";

    /// <summary>The JWK thumbprint claim member under <c>cnf</c> (RFC 9449 §7.2).</summary>
    public const string JktClaimMember = "jkt";

    /// <summary>
    /// Internal handoff claim used until the OpenIddict token principals have
    /// been prepared. It is never emitted in a token.
    /// </summary>
    internal const string BindingThumbprintClaimType = "sufficit_private_dpop_jkt";

    // jti replay cache: bounded by TTL so a proof cannot be reused after its
    // window. RFC 9449 §4.3 requires the RS/AS to ensure the same jti is not
    // used twice within the proof's validity window.
    private static readonly TimeSpan JtiCacheTtl = TimeSpan.FromMinutes(5);
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<DpopProofValidator> _logger;
    private readonly IDpopReplayCache? _replayCache;

    public DpopProofValidator(TimeProvider? timeProvider, ILogger<DpopProofValidator> logger)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _logger = logger;
        _replayCache = null; // fallback: in-process ConcurrentDictionary
    }

    /// <summary>
    /// Full constructor with a distributed replay cache. When provided, jti
    /// replay detection spans replicas. When null, falls back to the in-process
    /// ConcurrentDictionary (single-instance only).
    /// </summary>
    public DpopProofValidator(
        TimeProvider? timeProvider,
        ILogger<DpopProofValidator> logger,
        IDpopReplayCache? replayCache)
        : this(timeProvider, logger)
    {
        _replayCache = replayCache;
    }

    /// <summary>
    /// Validates a DPoP proof header value against the HTTP request it
    /// accompanies. Returns null (with a logged reason) when the proof is
    /// absent/malformed/fails validation, so the caller can decide whether to
    /// reject the request or fall back to bearer (depending on policy).
    /// </summary>
    /// <param name="dpopHeader">The raw value of the HTTP <c>DPoP</c> header.</param>
    /// <param name="httpMethod">The request method (<c>htm</c> claim target).</param>
    /// <param name="httpUrl">The request URL without query/fragement (<c>htu</c> target).</param>
    /// <param name="expectedNonce">The nonce the AS previously challenged the
    /// client with (via the <c>DPoP-Nonce</c> response header). When non-null,
    /// the proof MUST carry the same nonce in its <c>nonce</c> claim.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    public async Task<DpopProof?> ValidateAsync(
        string? dpopHeader,
        string httpMethod,
        string httpUrl,
        string? expectedNonce,
        CancellationToken cancellationToken,
        string? accessToken = null)
    {
        if (string.IsNullOrWhiteSpace(dpopHeader))
        {
            _logger.LogDebug("DPoP proof absent (no DPoP header).");
            return null;
        }

        JsonWebToken jwt;
        try
        {
            jwt = new JsonWebToken(dpopHeader);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "DPoP proof is not a parseable JWT.");
            return null;
        }

        // typ header MUST be exactly "dpop+jwt" (RFC 9449 §4.2).
        if (!string.Equals(jwt.Typ, DpopHeaderType, StringComparison.Ordinal))
        {
            _logger.LogWarning("DPoP proof typ header is '{Typ}', expected '{Expected}'.", jwt.Typ, DpopHeaderType);
            return null;
        }

        // L4 fix (eval L4): restrict the JWS alg to the set advertised in
        // discovery (dpop_signing_alg_values_supported = ES256, RS256). Without
        // this, the validator would accept any asymmetric alg the handler
        // supports (ES384, PS256, etc.) — a hardening gap vs the advertised
        // capability.
        if (!jwt.TryGetHeaderValue("alg", out string alg)
            || (alg != "ES256" && alg != "RS256"))
        {
            _logger.LogWarning("DPoP proof alg '{Alg}' is not in the advertised set (ES256, RS256).", alg);
            return null;
        }

        // Extract the client's public key from the embedded jwk header. The
        // proof is signed with the corresponding private key; validating
        // against this key proves possession.
        if (!jwt.TryGetHeaderValue("jwk", out string jwkJson))
        {
            _logger.LogWarning("DPoP proof has no jwk header; cannot verify signature.");
            return null;
        }

        JsonWebKey jwk;
        try
        {
            jwk = new JsonWebKey(jwkJson);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "DPoP proof jwk header is malformed.");
            return null;
        }

        // Validate the signature against the embedded key. We do NOT enforce an
        // issuer/audience here: DPoP proofs are not bearer tokens — their
        // security comes from the signature + htm/htu binding + jti replay
        // protection, not from who issued them.
        TokenValidationResult validationResult;
        try
        {
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = jwk,
                // DPoP proofs have very short validity; enforce a max skew.
                ClockSkew = TimeSpan.FromMinutes(1),
            };
            var handler = new JsonWebTokenHandler();
            validationResult = await handler.ValidateTokenAsync(dpopHeader, validationParameters);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "DPoP proof signature validation failed.");
            return null;
        }

        if (!validationResult.IsValid)
        {
            _logger.LogWarning("DPoP proof validation failed: {Error}", validationResult.Exception?.Message);
            return null;
        }

        // htm claim: HTTP method. Case-sensitive match per RFC 9449 §4.3.
        if (!jwt.TryGetPayloadValue("htm", out string htm)
            || !string.Equals(htm, httpMethod, StringComparison.Ordinal))
        {
            _logger.LogWarning("DPoP proof htm claim mismatch: got '{Got}', expected '{Expected}'.", htm, httpMethod);
            return null;
        }

        // htu claim: HTTP URL without query/fragment. Compare case-sensitively,
        // but tolerate trailing-slash differences (a common client/server drift).
        if (!jwt.TryGetPayloadValue("htu", out string htu)
            || !UrisMatch(htu, httpUrl))
        {
            _logger.LogWarning("DPoP proof htu claim mismatch: got '{Got}', expected '{Expected}'.", htu, httpUrl);
            return null;
        }

        // iat/exp: require an explicit short lifetime. Relying only on the
        // in-memory jti cache would allow a captured proof to become usable
        // again after cache eviction.
        if (!jwt.TryGetPayloadValue("iat", out long issuedAt)
            || !jwt.TryGetPayloadValue("exp", out long expiresAt))
        {
            _logger.LogWarning("DPoP proof must contain both iat and exp claims.");
            return null;
        }
        var nowSeconds = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        if (issuedAt > nowSeconds + 60 || nowSeconds - issuedAt > (long)JtiCacheTtl.TotalSeconds)
        {
            _logger.LogWarning("DPoP proof lifetime is outside the allowed replay window.");
            return null;
        }
        if (expiresAt <= nowSeconds
            || expiresAt <= issuedAt
            || expiresAt - issuedAt > (long)JtiCacheTtl.TotalSeconds)
        {
            _logger.LogWarning("DPoP proof exp is outside the allowed replay window.");
            return null;
        }

        // A proof presented to a protected resource MUST bind the exact access
        // token through ath (RFC 9449 §4.2). Token-endpoint proofs don't carry
        // ath, so this check is enabled only when the caller supplies a token.
        if (accessToken is not null)
        {
            var expectedAth = Base64UrlEncoder.Encode(
                SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
            if (!jwt.TryGetPayloadValue("ath", out string ath)
                || !string.Equals(ath, expectedAth, StringComparison.Ordinal))
            {
                _logger.LogWarning("DPoP proof ath claim does not match the access token.");
                return null;
            }
        }

        // jti: unique proof identifier. RFC 9449 §4.3 requires the AS/RS to
        // ensure the same jti is not reused within the proof's validity window.
        if (!jwt.TryGetPayloadValue("jti", out string jti) || string.IsNullOrWhiteSpace(jti))
        {
            _logger.LogWarning("DPoP proof has no jti claim.");
            return null;
        }
        if (IsReplayedJti(jti))
        {
            _logger.LogWarning("DPoP proof jti '{Jti}' was already used (replay rejected).", jti);
            return null;
        }

        // nonce: if the AS issued a nonce challenge (DPoP-Nonce response
        // header), the client's NEXT proof MUST include it. We only enforce
        // this when expectedNonce is non-null (the AS controls when to demand
        // nonces — see the DpopNonceIssuer).
        if (expectedNonce is not null)
        {
            if (!jwt.TryGetPayloadValue("nonce", out string nonce)
                || !string.Equals(nonce, expectedNonce, StringComparison.Ordinal))
            {
                _logger.LogWarning("DPoP proof nonce mismatch (AS expected a nonce challenge response).");
                return null;
            }
        }

        // Compute the JWK thumbprint (cnf.jkt) — the value that binds the
        // access token to this key. RFC 9449 §7.2: the cnf claim is a JSON
        // object {"jkt": "<base64url-thumbprint>"}. ComputeJwkThumbprint
        // returns raw bytes; the cnf.jkt is the base64url encoding of them.
        var thumbprintBytes = jwk.ComputeJwkThumbprint();
        var thumbprint = Base64UrlEncoder.Encode(thumbprintBytes);

        _logger.LogDebug("DPoP proof valid; binding token to key thumbprint {Thumbprint}.", thumbprint);
        return new DpopProof(jti, thumbprint, jwk);
    }

    /// <summary>
    /// Compares two htu values, tolerating trailing-slash differences. RFC 9449
    /// §4.3 compares the htu claim against the request URL without query/fragment.
    /// </summary>
    private static bool UrisMatch(string claimed, string actual)
    {
        var a = claimed.TrimEnd('/');
        var b = actual.TrimEnd('/');
        return string.Equals(a, b, StringComparison.Ordinal);
    }

    // Simplest-correct replay cache: a ConcurrentDictionary of jti -> expiry.
    // Bounded by lazy eviction on read; for an AS at Sufficit's scale this is
    // fine. A distributed AS would swap this for a shared cache (Redis) — but
    // replay protection degrades gracefully across replicas (a proof reused on
    // a different replica within the window still gets a token; the blast
    // radius is a single extra token, revocable via introspection).
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTimeOffset> _seenJtis = new();

    private bool IsReplayedJti(string jti)
    {
        // Distributed cache path: works across replicas.
        if (_replayCache is not null)
        {
            return _replayCache.IsReplay(jti, JtiCacheTtl);
        }

        // Fallback: in-process ConcurrentDictionary (single-instance only).
        var now = _timeProvider.GetUtcNow();
        foreach (var kv in _seenJtis)
        {
            if (kv.Value < now)
            {
                _seenJtis.TryRemove(kv.Key, out _);
            }
        }
        return !_seenJtis.TryAdd(jti, now + JtiCacheTtl);
    }
}

/// <summary>
/// A successfully-validated DPoP proof, carrying the material needed to
/// sender-constrain the issued access token.
/// </summary>
public sealed record DpopProof(string Jti, string KeyThumbprint, JsonWebKey PublicKey);
