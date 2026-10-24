using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

namespace Sufficit.Identity.Tests.Infrastructure;

/// <summary>
/// Minimal WebAuthn software authenticator: one ES256 credential, "none"
/// attestation, user presence and user verification always asserted. It
/// produces the JSON a browser hands back from
/// <c>navigator.credentials.create/get</c>, so tests can drive the real
/// ASP.NET Identity ceremony over HTTP without a browser.
/// </summary>
internal sealed class SoftwarePasskeyAuthenticator : IDisposable
{
    // UP (0x01) | UV (0x04); AT (0x40) is added for attestation.
    private const byte PresentAndVerified = 0x05;
    private const byte AttestedCredentialData = 0x40;

    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly byte[] _credentialId = RandomNumberGenerator.GetBytes(32);
    private uint _signCount;

    public string CredentialId => WebEncoders.Base64UrlEncode(_credentialId);

    /// <summary>Answers creation options with a registration credential.</summary>
    public string CreateAttestation(JsonElement creationOptions, string origin)
    {
        var challenge = creationOptions.GetProperty("challenge").GetString()!;
        var rpId = creationOptions.GetProperty("rp").TryGetProperty("id", out var id)
            ? id.GetString()!
            : new Uri(origin).Host;
        var clientData = ClientData("webauthn.create", challenge, origin);

        var parameters = _key.ExportParameters(includePrivateParameters: false);
        var coseKey = Cbor.Map(
            (Cbor.Int(1), Cbor.Int(2)),      // kty: EC2
            (Cbor.Int(3), Cbor.Int(-7)),     // alg: ES256
            (Cbor.Int(-1), Cbor.Int(1)),     // crv: P-256
            (Cbor.Int(-2), Cbor.Bytes(parameters.Q.X!)),
            (Cbor.Int(-3), Cbor.Bytes(parameters.Q.Y!)));

        var authenticatorData = Concat(
            SHA256.HashData(Encoding.UTF8.GetBytes(rpId)),
            [(byte)(PresentAndVerified | AttestedCredentialData)],
            BigEndian(_signCount),
            new byte[16], // AAGUID
            [(byte)(_credentialId.Length >> 8), (byte)_credentialId.Length],
            _credentialId,
            coseKey);
        var attestationObject = Cbor.Map(
            (Cbor.Text("fmt"), Cbor.Text("none")),
            (Cbor.Text("attStmt"), Cbor.Map()),
            (Cbor.Text("authData"), Cbor.Bytes(authenticatorData)));

        return JsonSerializer.Serialize(new
        {
            id = CredentialId,
            rawId = CredentialId,
            type = "public-key",
            authenticatorAttachment = "platform",
            clientExtensionResults = new { },
            response = new
            {
                clientDataJSON = WebEncoders.Base64UrlEncode(clientData),
                attestationObject = WebEncoders.Base64UrlEncode(attestationObject),
                transports = new[] { "internal" },
            },
        });
    }

    /// <summary>Answers request options with an assertion credential.</summary>
    public string CreateAssertion(
        JsonElement requestOptions,
        string origin,
        string userHandle)
    {
        var challenge = requestOptions.GetProperty("challenge").GetString()!;
        var rpId = requestOptions.TryGetProperty("rpId", out var id)
            ? id.GetString()!
            : new Uri(origin).Host;
        var clientData = ClientData("webauthn.get", challenge, origin);
        _signCount++;
        var authenticatorData = Concat(
            SHA256.HashData(Encoding.UTF8.GetBytes(rpId)),
            [PresentAndVerified],
            BigEndian(_signCount));
        var signature = _key.SignData(
            Concat(authenticatorData, SHA256.HashData(clientData)),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);

        return JsonSerializer.Serialize(new
        {
            id = CredentialId,
            rawId = CredentialId,
            type = "public-key",
            authenticatorAttachment = "platform",
            clientExtensionResults = new { },
            response = new
            {
                clientDataJSON = WebEncoders.Base64UrlEncode(clientData),
                authenticatorData = WebEncoders.Base64UrlEncode(authenticatorData),
                signature = WebEncoders.Base64UrlEncode(signature),
                userHandle,
            },
        });
    }

    public void Dispose() => _key.Dispose();

    private static byte[] ClientData(string type, string challenge, string origin) =>
        JsonSerializer.SerializeToUtf8Bytes(new
        {
            type,
            challenge,
            origin,
            crossOrigin = false,
        });

    private static byte[] BigEndian(uint value) =>
        [(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value];

    private static byte[] Concat(params byte[][] parts) =>
        parts.SelectMany(part => part).ToArray();

    /// <summary>The handful of CBOR shapes WebAuthn needs (RFC 8949).</summary>
    private static class Cbor
    {
        public static byte[] Int(long value) => value >= 0
            ? Head(0, (ulong)value)
            : Head(1, (ulong)(-1 - value));

        public static byte[] Bytes(byte[] value) => Concat(Head(2, (ulong)value.Length), value);

        public static byte[] Text(string value)
        {
            var utf8 = Encoding.UTF8.GetBytes(value);
            return Concat(Head(3, (ulong)utf8.Length), utf8);
        }

        public static byte[] Map(params (byte[] Key, byte[] Value)[] entries) =>
            Concat([Head(5, (ulong)entries.Length), .. entries.SelectMany(entry => new[] { entry.Key, entry.Value })]);

        private static byte[] Head(int major, ulong length)
        {
            var type = (byte)(major << 5);
            return length switch
            {
                < 24 => [(byte)(type | (byte)length)],
                <= byte.MaxValue => [(byte)(type | 24), (byte)length],
                <= ushort.MaxValue => [(byte)(type | 25), (byte)(length >> 8), (byte)length],
                _ => throw new ArgumentOutOfRangeException(nameof(length)),
            };
        }
    }
}
