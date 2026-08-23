using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Clients;

/// <summary>
/// Validation rules for the public key material a client registers for
/// <c>private_key_jwt</c> authentication (its <c>jwks_uri</c> and inline JWKS).
/// </summary>
/// <remarks>
/// Extracted from <c>ClientManagementService</c>, where it sat among roughly
/// forty other static helpers inside a 3,200-line class. These rules decide
/// whether a key is acceptable for authenticating a client, so they are worth
/// reading, reviewing and testing on their own rather than by scrolling past
/// unrelated CRUD. Behavior is unchanged — the reason codes and messages are
/// part of the API contract and are reproduced exactly.
/// </remarks>
internal static class ClientJwksPolicy
{
    // A JWKS is a handful of public keys; anything past this is abuse, not use.
    private const int MaximumJwksBytes = 64 * 1024;
    private const int MinimumRsaModulusBytes = 256;   // 2048-bit
    private const int MaximumRsaExponentBytes = 8;
    private const int MaximumKeys = 10;

    /// <summary>
    /// JWK members that carry PRIVATE or symmetric material. Their presence is
    /// rejected outright: a client that pastes its private key into the
    /// management API must be told, not silently trusted with it at rest.
    /// </summary>
    private static readonly string[] PrivateKeyParameters =
        ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

    internal static Uri? ValidateJwksUri(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri)
            || !PublicHttpsUriPolicy.IsAllowed(uri))
        {
            throw new ManagementValidationException(
                "jwks_uri_invalid",
                "jwksUri must be a public absolute HTTPS URI without user-info or fragment.",
                "jwksUri");
        }

        return uri;
    }

    internal static JsonWebKeySet? ValidatePublicJwks(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }
        if (value.Length > MaximumJwksBytes)
        {
            throw new ManagementValidationException(
                "jwks_too_large",
                "O conjunto JWKS não pode ultrapassar 64 KiB.",
                "jwksJson");
        }

        try
        {
            using var document = JsonDocument.Parse(value, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16,
            });
            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !document.RootElement.TryGetProperty("keys", out var keys)
                || keys.ValueKind != JsonValueKind.Array
                || keys.GetArrayLength() is < 1 or > MaximumKeys)
            {
                throw new ManagementValidationException(
                    "jwks_keys_invalid",
                    "O JWKS deve conter entre 1 e 10 chaves públicas em 'keys'.",
                    "jwksJson");
            }

            var keyIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (var key in keys.EnumerateArray())
            {
                ValidateKey(key, keyIds);
            }

            return new JsonWebKeySet(document.RootElement.GetRawText());
        }
        catch (JsonException exception)
        {
            throw new ManagementValidationException(
                "jwks_json_invalid",
                $"O JWKS não é um JSON válido: {exception.Message}",
                "jwksJson");
        }
        catch (ArgumentException exception)
        {
            throw new ManagementValidationException(
                "jwks_json_invalid",
                $"O JWKS não pôde ser interpretado: {exception.Message}",
                "jwksJson");
        }
    }

    private static void ValidateKey(JsonElement key, HashSet<string> keyIds)
    {
        if (key.ValueKind != JsonValueKind.Object)
        {
            throw new ManagementValidationException(
                "jwks_key_invalid",
                "Cada item de 'keys' deve ser uma chave JWK pública.",
                "jwksJson");
        }

        foreach (var privateParameter in PrivateKeyParameters)
        {
            if (key.TryGetProperty(privateParameter, out _))
            {
                throw new ManagementValidationException(
                    "jwks_private_material_forbidden",
                    "O Identity aceita apenas chaves públicas. Remova parâmetros privados ou simétricos do JWKS.",
                    "jwksJson");
            }
        }

        var kty = RequiredJwkString(key, "kty");
        if (kty is not (JsonWebAlgorithmsKeyTypes.RSA
            or JsonWebAlgorithmsKeyTypes.EllipticCurve))
        {
            throw new ManagementValidationException(
                "jwks_key_type_unsupported",
                "Use somente chaves públicas RSA ou EC para private_key_jwt.",
                "jwksJson");
        }

        var kid = RequiredJwkString(key, "kid");
        if (!keyIds.Add(kid))
        {
            throw new ManagementValidationException(
                "jwks_kid_duplicate",
                "Cada chave pública deve possuir um kid único.",
                "jwksJson");
        }

        if (key.TryGetProperty("use", out var use)
            && (use.ValueKind != JsonValueKind.String
                || !string.Equals(
                    use.GetString(),
                    JsonWebKeyUseNames.Sig,
                    StringComparison.Ordinal)))
        {
            throw new ManagementValidationException(
                "jwks_use_invalid",
                "Chaves de autenticação devem usar 'use': 'sig' ou omitir o campo.",
                "jwksJson");
        }

        if (kty == JsonWebAlgorithmsKeyTypes.RSA)
        {
            ValidateRsaKey(key);
        }
        else
        {
            ValidateEcKey(key);
        }

        ValidateAlgorithm(key, kty);
    }

    private static void ValidateRsaKey(JsonElement key)
    {
        var modulus = RequiredJwkString(key, "n");
        var exponent = RequiredJwkString(key, "e");
        if (!TryGetBase64UrlByteLength(modulus, out var modulusBytes)
            || modulusBytes < MinimumRsaModulusBytes
            || !TryGetBase64UrlByteLength(exponent, out var exponentBytes)
            || exponentBytes is < 1 or > MaximumRsaExponentBytes)
        {
            throw new ManagementValidationException(
                "jwks_rsa_key_too_small",
                "Chaves RSA devem possuir pelo menos 2048 bits.",
                "jwksJson");
        }
    }

    private static void ValidateEcKey(JsonElement key)
    {
        var curve = RequiredJwkString(key, "crv");
        if (curve is not ("P-256" or "P-384" or "P-521"))
        {
            throw new ManagementValidationException(
                "jwks_curve_unsupported",
                "Use curvas P-256, P-384 ou P-521.",
                "jwksJson");
        }

        var x = RequiredJwkString(key, "x");
        var y = RequiredJwkString(key, "y");
        // The coordinate width is fixed by the curve; a mismatch means the key
        // does not describe the curve it claims.
        var coordinateBytes = curve switch
        {
            "P-256" => 32,
            "P-384" => 48,
            _ => 66,
        };
        if (!TryGetBase64UrlByteLength(x, out var xBytes)
            || !TryGetBase64UrlByteLength(y, out var yBytes)
            || xBytes != coordinateBytes
            || yBytes != coordinateBytes)
        {
            throw new ManagementValidationException(
                "jwks_ec_coordinates_invalid",
                "As coordenadas EC não correspondem à curva informada.",
                "jwksJson");
        }
    }

    private static void ValidateAlgorithm(JsonElement key, string kty)
    {
        if (!key.TryGetProperty("alg", out var algorithm))
        {
            return;
        }

        var alg = algorithm.ValueKind == JsonValueKind.String
            ? algorithm.GetString()
            : null;
        if (alg is not ("RS256" or "RS384" or "RS512"
            or "PS256" or "PS384" or "PS512"
            or "ES256" or "ES384" or "ES512"))
        {
            throw new ManagementValidationException(
                "jwks_algorithm_unsupported",
                "O algoritmo da chave deve ser RS*, PS* ou ES* com SHA-256/384/512.",
                "jwksJson");
        }

        if ((kty == JsonWebAlgorithmsKeyTypes.RSA
                && !alg.StartsWith("RS", StringComparison.Ordinal)
                && !alg.StartsWith("PS", StringComparison.Ordinal))
            || (kty == JsonWebAlgorithmsKeyTypes.EllipticCurve
                && !alg.StartsWith("ES", StringComparison.Ordinal)))
        {
            throw new ManagementValidationException(
                "jwks_algorithm_key_type_mismatch",
                "O algoritmo informado não corresponde ao tipo da chave pública.",
                "jwksJson");
        }
    }

    private static string RequiredJwkString(JsonElement key, string property)
    {
        if (!key.TryGetProperty(property, out var value)
            || value.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(value.GetString()))
        {
            throw new ManagementValidationException(
                "jwks_key_parameter_required",
                $"Cada chave pública deve informar '{property}'.",
                "jwksJson");
        }

        return value.GetString()!;
    }

    private static bool TryGetBase64UrlByteLength(string value, out int length)
    {
        try
        {
            length = WebEncoders.Base64UrlDecode(value).Length;
            return true;
        }
        catch (FormatException)
        {
            length = 0;
            return false;
        }
    }
}
