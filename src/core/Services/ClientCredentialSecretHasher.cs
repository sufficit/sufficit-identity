using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Core.Services;

/// <summary>
/// Hashes additional OAuth client secrets without depending on OpenIddict's
/// persistence model. The encoded ASP.NET Core Identity format carries its
/// algorithm and work-factor metadata so future versions can verify and
/// progressively upgrade existing hashes.
/// </summary>
public interface IClientCredentialSecretHasher
{
    string Hash(string secret);

    bool Verify(string hash, string secret);
}

public sealed class ClientCredentialSecretHasher : IClientCredentialSecretHasher
{
    private const int IterationCount = 210_000;

    private readonly PasswordHasher<OAuthClientCredential> _hasher = new(
        Options.Create(new PasswordHasherOptions
        {
            CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV3,
            IterationCount = IterationCount,
        }));

    public string Hash(string secret)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        return _hasher.HashPassword(new OAuthClientCredential(), secret);
    }

    public bool Verify(string hash, string secret)
    {
        ArgumentException.ThrowIfNullOrEmpty(hash);
        ArgumentException.ThrowIfNullOrEmpty(secret);

        return _hasher.VerifyHashedPassword(
            new OAuthClientCredential(),
            hash,
            secret) is not PasswordVerificationResult.Failed;
    }
}
