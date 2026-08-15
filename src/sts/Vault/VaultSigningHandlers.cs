using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.STS.Vault;

/// <summary>Maps a stored signing JWK's algorithm to IdentityModel ids.</summary>
internal static class VaultSigningAlgorithmMap
{
    public static string AlgorithmForJwk(string publicJwk) =>
        Sufficit.Identity.Vault.SigningAlgorithms.FromJwk(publicJwk) switch
        {
            Sufficit.Identity.Vault.SigningAlgorithms.RsaPssSha256 =>
                Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSsaPssSha256,
            Sufficit.Identity.Vault.SigningAlgorithms.EcdsaSha256 =>
                Microsoft.IdentityModel.Tokens.SecurityAlgorithms.EcdsaSha256,
            _ => Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSha256,
        };
}

/// <summary>Injects a vault-backed signing key into OpenIddict token issuance.</summary>
public sealed class VaultSigningCredentialsHandler : IOpenIddictServerHandler<
    OpenIddictServerEvents.GenerateTokenContext>
{
    private readonly IKeyVault _keyVault;
    private readonly VaultOptions _options;

    public VaultSigningCredentialsHandler(IKeyVault keyVault, VaultOptions options)
    {
        _keyVault = keyVault;
        _options = options;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<OpenIddictServerEvents.GenerateTokenContext>()
            .UseScopedHandler<VaultSigningCredentialsHandler>()
            // Run immediately before IdentityModel creates the JWT, after all
            // built-in credential selection handlers have completed.
            .SetOrder(OpenIddictServerHandlers.Protection.GenerateIdentityModelToken.Descriptor.Order - 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(OpenIddictServerEvents.GenerateTokenContext context)
    {
        var keys = await _keyVault.GetSigningKeysAsync(_options.SigningKeyName,
            CancellationToken.None);
        var current = keys.FirstOrDefault(key =>
                key.Status == VaultSigningKeyStatus.Active)
            ?? throw new InvalidOperationException(
                $"Vault signing key '{_options.SigningKeyName}' is not available.");
        var securityKey = new VaultSigningSecurityKey(current, _keyVault);

        // A6 (eval 2026-08-14): sign with the algorithm embedded in THIS
        // key version's JWK (RS256/PS256/ES256), never a global constant —
        // rotation can move between families and in-flight versions keep
        // their own.
        var credentials = new SigningCredentials(
            securityKey,
            VaultSigningAlgorithmMap.AlgorithmForJwk(current.PublicJwk));
        context.SigningCredentials = credentials;
        // AttachTokenMetadata may already have materialized the descriptor;
        // update it as well so IdentityModel cannot retain the bootstrap key.
        if (context.SecurityTokenDescriptor is not null)
        {
            context.SecurityTokenDescriptor.SigningCredentials = credentials;
        }
    }
}

/// <summary>Publishes all retained vault signing JWKs during JWKS discovery.</summary>
public sealed class VaultJsonWebKeySetHandler : IOpenIddictServerHandler<
    OpenIddictServerEvents.HandleJsonWebKeySetRequestContext>
{
    private readonly IKeyVault _keyVault;
    private readonly VaultOptions _options;

    public VaultJsonWebKeySetHandler(IKeyVault keyVault, VaultOptions options)
    {
        _keyVault = keyVault;
        _options = options;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<OpenIddictServerEvents.HandleJsonWebKeySetRequestContext>()
            .UseScopedHandler<VaultJsonWebKeySetHandler>()
            .SetOrder(OpenIddictServerHandlers.Discovery.AttachSigningKeys.Descriptor.Order + 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(OpenIddictServerEvents.HandleJsonWebKeySetRequestContext context)
    {
        var keys = await _keyVault.GetSigningKeysAsync(_options.SigningKeyName,
            CancellationToken.None);
        foreach (var key in keys)
        {
            var jwk = new JsonWebKey(key.PublicJwk)
            {
                KeyId = key.KeyId,
                Alg = VaultSigningAlgorithmMap.AlgorithmForJwk(key.PublicJwk),
                Use = "sig",
            };
            context.Keys.Add(jwk);
        }
    }
}
