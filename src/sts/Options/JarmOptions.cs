using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// JWT Secured Authorization Response Mode (JARM) configuration. The STS
/// signs the complete authorization response and returns it in a single
/// <c>response</c> parameter. This capability is independent of FAPI 2.0.
/// </summary>
public sealed class JarmOptions
{
    /// <summary>Master switch. Default <c>false</c>.</summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// Signed response lifetime in seconds. Kept short to bound replay;
    /// values outside 1..600 are rejected during startup.
    /// </summary>
    public int LifetimeSeconds { get; init; } = 120;

    /// <summary>
    /// JARM encryption (JWE) configuration. When set, authorization responses
    /// are signed AND encrypted (signed-then-encrypted, the FAPI 2.0 Advancing
    /// Profile shape). When null (default), responses remain signed-only.
    /// </summary>
    public JarmEncryptionOptions Encryption { get; init; } = new();
}
/// <summary>
/// JWE encryption settings for JARM responses. The STS can encrypt the signed
/// JWT response to an RSA or EC public key registered in each client's JWKS.
/// The receiver decrypts with its matching private key. Encryption is an
/// optional JARM confidentiality mode; FAPI 2.0 does not require it for the
/// authorization code response.
/// </summary>
public sealed class JarmEncryptionOptions
{
    /// <summary>
    /// Master switch for JWE encryption. When false (default), JARM responses
    /// are signed-only even when <see cref="JarmOptions.Enabled"/> is true.
    /// </summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// Deprecated and ignored. Recipient keys must come from client metadata.
    /// </summary>
    public string? Path { get; init; }

    /// <summary>
    /// Deprecated and ignored with <see cref="Path"/>.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// JWE <c>alg</c> (key management) algorithm for RSA recipient keys.
    /// Defaults to <c>RSA-OAEP-256</c> (RSA-OAEP with SHA-256). The legacy
    /// <c>RSA-OAEP</c> (SHA-1) is discouraged. Ignored for EC recipient keys, which use
    /// <see cref="EcKeyManagementAlgorithm"/>.
    /// </summary>
    public string KeyManagementAlgorithm { get; init; } = "RSA-OAEP-256";

    /// <summary>
    /// JWE <c>alg</c> (key management) algorithm for EC recipient keys.
    /// Defaults to <c>ECDH-ES+A256KW</c>. Used when a FAPI/OIDC client
    /// registers an elliptic-curve (rather than RSA) encryption key in its
    /// JWKS.
    /// </summary>
    public string EcKeyManagementAlgorithm { get; init; } = "ECDH-ES+A256KW";

    /// <summary>
    /// JWE <c>enc</c> (content encryption) algorithm. Defaults to
    /// <c>A256CBC-HS512</c> (the value compatible with RSA key transport in
    /// Microsoft IdentityModel — <c>A256GCM</c> requires symmetric keywrap).
    /// </summary>
    public string ContentEncryptionAlgorithm { get; init; } = "A256CBC-HS512";
}
