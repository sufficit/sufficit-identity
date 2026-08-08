using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Sufficit.Identity.STS.Ciba;

/// <summary>
/// Generates CIBA identifiers (<c>auth_req_id</c> and internal consumption
/// tokens) with full CSPRNG entropy.
/// </summary>
/// <remarks>
/// The <c>auth_req_id</c> is a bearer credential during the CIBA polling phase
/// (OpenID Connect CIBA Core 1.0 §7.3): whoever presents it at the token
/// endpoint polls for the authentication result. It must therefore be
/// unguessable and carry no exploitable structure.
///
/// This intentionally uses 256 bits of CSPRNG output rather than
/// <c>Guid.NewGuid()</c>. A v4 GUID carries ~122 bits of entropy; a v7 GUID
/// carries even less (~74 random bits) AND embeds a millisecond creation
/// timestamp, leaking when the request was created and reducing
/// unpredictability — the wrong trade-off for a bearer secret. 256 bits of raw
/// CSPRNG, base64url-encoded, is both stronger and consistent with how the SSF
/// stream secrets and DPoP nonces are generated elsewhere in this codebase.
/// </remarks>
internal static class CibaIdentifier
{
    /// <summary>Entropy in bytes (256 bits) for a CIBA identifier.</summary>
    private const int EntropyBytes = 32;

    /// <summary>
    /// Returns a fresh, unguessable, URL-safe CIBA identifier.
    /// </summary>
    public static string Create()
        => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(EntropyBytes));
}
