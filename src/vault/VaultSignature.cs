using System.Collections.Concurrent;
using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Vault.Crypto;

namespace Sufficit.Identity.Vault;

internal static class VaultSignature
{
    private const string Scheme = "sig1";

    public static string Format(string keyName, int version, byte[] signature) =>
        $"{Scheme}.{keyName}:{version}.{WebEncoders.Base64UrlEncode(signature)}";

    public static ParsedVaultSignature Parse(string value)
    {
        var parts = value.Split('.', StringSplitOptions.None);
        if (parts.Length != 3 || parts[0] != Scheme)
            throw new FormatException("Unsupported vault signature format.");
        var key = parts[1].Split(':', 2);
        if (key.Length != 2 || !int.TryParse(key[1], out var version)
            || version < 1 || string.IsNullOrWhiteSpace(key[0]))
            throw new FormatException("Invalid vault signing key identifier.");
        return new ParsedVaultSignature(
            key[0],
            version,
            WebEncoders.Base64UrlDecode(parts[2]));
    }
}

internal sealed record ParsedVaultSignature(
    string KeyName,
    int KeyVersion,
    byte[] Signature);
