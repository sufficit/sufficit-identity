using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.STS.Vault;

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
        var current = keys.OrderByDescending(key => key.KeyVersion).FirstOrDefault()
            ?? throw new InvalidOperationException(
                $"Vault signing key '{_options.SigningKeyName}' is not available.");
        var securityKey = new VaultSigningSecurityKey(current, _keyVault);
        var credentials = new SigningCredentials(
            securityKey,
            SecurityAlgorithms.RsaSha256);
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
                Alg = SecurityAlgorithms.RsaSha256,
                Use = "sig",
            };
            context.Keys.Add(jwk);
        }
    }
}
