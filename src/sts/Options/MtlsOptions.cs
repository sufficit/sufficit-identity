using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Mutual TLS (mTLS) client authentication and sender-constrained access
/// tokens (RFC 8705). mTLS is a prerequisite of FAPI 2.0 and a stronger
/// alternative to client secrets for confidential clients: the client
/// authenticates with an X.509 certificate at the TLS layer against
/// MTLS-aliased endpoint paths (e.g. <c>/connect/token</c> served under a
/// distinct path that requires a client certificate).
/// </summary>
/// <remarks>
/// <b>Opt-in (default <see cref="Enabled"/>=<c>false</c>).</b> mTLS requires
/// the HOST (Kestrel/nginx) to be configured to request and validate client
/// certificates at the TLS handshake — that is deployment configuration, not
/// something this option alone can enable. When <see cref="Enabled"/> is true,
/// the STS registers the MTLS endpoint aliases (so clients can target them)
/// and advertises <c>tls_client_certificate_bound_access_tokens=true</c> in
/// discovery. See <c>src/server/Program.cs</c> and the appsettings template
/// for the host-side configuration required.
/// <para><b>private_key_jwt</b> (RFC 7523) is enabled by OpenIddict
/// unconditionally and is NOT gated here — it is available regardless of this
/// flag. mTLS and private_key_jwt together cover the "strong client auth"
/// requirement of FAPI 2.0.</para>
/// </remarks>
public sealed class MtlsOptions
{
    /// <summary>
    /// When <c>true</c>, the STS registers MTLS endpoint aliases and advertises
    /// mTLS sender-constrained token support in discovery. Default
    /// <c>false</c> — the host must be configured for client certificates first
    /// (otherwise the MTLS-aliased paths would 404 at the TLS layer).
    /// </summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// Optional public base URL used for the RFC 8705 endpoint aliases in
    /// discovery. This is useful when the mTLS terminator is isolated on a
    /// dedicated host or port, while the ordinary issuer remains unchanged.
    /// When empty, the configured issuer is used.
    /// </summary>
    public string? EndpointBaseUrl { get; init; }

    /// <summary>
    /// Explicit statement of where client-certificate validation occurs.
    /// Enabling mTLS with Unattested is rejected during startup.
    /// </summary>
    public MtlsDeploymentMode DeploymentMode { get; init; } =
        MtlsDeploymentMode.Unattested;

    /// <summary>
    /// Legacy configuration-only SHA-256 pins. New deployments must register
    /// public certificates through the client JWKS/management API so the same
    /// binding is used by native client authentication and sender constraint.
    /// Kept temporarily so older configuration files continue to bind.
    /// </summary>
    public Dictionary<string, HashSet<string>> ClientCertificateThumbprints { get; init; } =
        new(StringComparer.Ordinal);

    /// <summary>
    /// Public PEM/DER files containing the root and optional intermediate
    /// certificate authorities trusted for RFC 8705 <c>tls_client_auth</c>.
    /// The files must never contain private keys. When this collection is
    /// empty, the recommended <c>self_signed_tls_client_auth</c> method remains
    /// available but PKI-based client authentication is not advertised.
    /// </summary>
    public string[] TrustedCertificateAuthorityPaths { get; init; } = [];

    /// <summary>
    /// Builds the platform X.509 chain in addition to the explicit client pin.
    /// Keep enabled in production; private PKI roots must be installed in the
    /// host trust store.
    /// </summary>
    public bool RequireValidCertificateChain { get; init; } = true;

    /// <summary>
    /// Certificate-revocation strategy used while building the platform chain.
    /// The secure default performs online CRL/OCSP retrieval.
    /// </summary>
    public MtlsCertificateRevocationMode RevocationMode { get; init; } =
        MtlsCertificateRevocationMode.Online;

    /// <summary>
    /// Controls whether an unavailable CRL/OCSP responder is denied. The
    /// default is fail-closed; the compatibility mode never permits an
    /// explicitly revoked, expired, untrusted or wrongly pinned certificate.
    /// </summary>
    public MtlsRevocationFailureMode RevocationFailureMode { get; init; } =
        MtlsRevocationFailureMode.FailClosed;

    /// <summary>Maximum platform chain URL retrieval time.</summary>
    public int RevocationTimeoutSeconds { get; init; } = 3;

    /// <summary>
    /// Header carrying the URL-encoded PEM or base64 DER certificate in
    /// TrustedProxy mode. It is removed before downstream middleware runs.
    /// </summary>
    public string ForwardedCertificateHeader { get; init; } =
        "X-Sufficit-Client-Certificate";

    /// <summary>
    /// CIDRs authorized specifically to assert the forwarded client
    /// certificate. This list is deliberately separate from general
    /// X-Forwarded-* proxy trust.
    /// </summary>
    public HashSet<string> TrustedProxyNetworks { get; init; } =
        new(StringComparer.Ordinal);
}
public enum MtlsDeploymentMode
{
    Unattested,
    DirectTls,
    TrustedProxy,
}
public enum MtlsCertificateRevocationMode
{
    NoCheck,
    Online,
    Offline,
}
public enum MtlsRevocationFailureMode
{
    FailClosed,
    AllowWhenUnavailable,
}
