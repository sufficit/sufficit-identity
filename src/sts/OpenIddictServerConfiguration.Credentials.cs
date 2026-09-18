using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.STS.Metrics;
using Sufficit.Identity.Vault;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS;

public static partial class ServiceCollectionExtensions
{
    /// <summary>
    /// Selects the token signing and encryption material: vault-managed keys, configured certificates, or development certificates.
    /// </summary>
    private static void ConfigureServerCredentials(
        OpenIddictServerBuilder server,
        VaultOptions vaultOptions,
        CertificateMaterial certificateMaterial,
        SigningCredentials auxiliarySigningCredentials,
        bool isDevelopmentEnvironment)
    {
        // -------------------------------------------------------------------
        // Signing/encryption certificates (SECURITY CRITICAL). Production
        // requires persistent X.509 certificates configured under
        // Sufficit:Identity:Certificates (PFX files loaded from disk);
        // ephemeral development certificates are only ever used when
        // ASPNETCORE_ENVIRONMENT=Development, so a misconfigured
        // production deployment fails fast at startup instead of
        // silently signing tokens with a throwaway, regenerated-on-
        // every-restart key.
        // (isDevelopmentEnvironment computed once, near the top of
        // AddSufficitIdentitySTS, and reused here via closure.)
        // -------------------------------------------------------------------
        if (vaultOptions.ManageSigningKeys)
        {
            // OpenIddict token signing is replaced by the vault
            // handler registered below. Certificates remain available
            // to auxiliary protocol JWT generators.
            // OpenIddict requires one asymmetric credential during
            // options validation; this bootstrap key is never selected
            // by GenerateTokenContext and is removed from JWKS by the
            // vault discovery handler.
            server.AddEphemeralSigningKey();
            // Auxiliary JWTs (logout/JARM/SSF/CIBA) still use the
            // protocol credential resolved above. Publish their
            // public halves alongside the vault keys without making
            // them the OpenIddict token-signing choice.
            foreach (var certificate in certificateMaterial.Signing)
            {
                server.AddSigningKey(new Microsoft.IdentityModel.Tokens.X509SecurityKey(certificate));
            }
            if (isDevelopmentEnvironment)
            {
                server.AddSigningKey(auxiliarySigningCredentials.Key);
            }
        }
        else if (certificateMaterial.Signing.Count > 0)
        {
            foreach (var certificate in certificateMaterial.Signing)
            {
                AddSigningCertificate(server, certificate);
            }
        }
        else if (isDevelopmentEnvironment)
        {
            server.AddDevelopmentSigningCertificate();
            // Publish the same ephemeral public key used to sign JARM,
            // SSF/CAEP, logout_token and CIBA JWTs. Without this extra
            // signing key those JWTs worked only in-process and could
            // not be verified through the advertised JWKS endpoint.
            server.AddSigningKey(auxiliarySigningCredentials.Key);
        }
        else
        {
            throw new InvalidOperationException(
                "No signing certificate configured. Production deployments " +
                "require 'Sufficit:Identity:Certificates:SigningPath' (and " +
                "SigningPassword, if the PFX is protected) to point to a " +
                "valid PFX file. Ephemeral development certificates are only " +
                "allowed when ASPNETCORE_ENVIRONMENT=Development.");
        }

        if (vaultOptions.ManageSigningKeys)
        {
            server.AddEventHandler(Vault.VaultSigningCredentialsHandler.Descriptor);
            server.AddEventHandler(Vault.VaultJsonWebKeySetHandler.Descriptor);
        }

        if (certificateMaterial.Encryption.Count > 0)
        {
            foreach (var certificate in certificateMaterial.Encryption)
            {
                server.AddEncryptionCertificate(certificate);
            }
        }
        else if (isDevelopmentEnvironment)
        {
            server.AddDevelopmentEncryptionCertificate();
        }
        else
        {
            throw new InvalidOperationException(
                "No encryption certificate configured. Production deployments " +
                "require 'Sufficit:Identity:Certificates:EncryptionPath' (and " +
                "EncryptionPassword, if the PFX is protected) to point to a " +
                "valid PFX file. Ephemeral development certificates are only " +
                "allowed when ASPNETCORE_ENVIRONMENT=Development.");
        }
    }

    /// <summary>
    /// Registers a configured signing certificate with OpenIddict.
    /// </summary>
    /// <remarks>
    /// OpenIddict infers the signature algorithm from the key, and its
    /// inference does not cover an X.509 certificate that holds an elliptic
    /// curve key: <c>AddSigningCertificate</c> throws "a signature algorithm
    /// cannot be automatically inferred from the signing key". EC keys are what
    /// a FAPI-grade deployment uses — the profile does not accept RS256 — so
    /// the credential is built here from the curve instead.
    /// </remarks>
    internal static void AddSigningCertificate(
        OpenIddictServerBuilder server,
        X509Certificate2 certificate)
    {
        // Not disposed: the key is used for the lifetime of the server.
        var ecdsa = certificate.GetECDsaPrivateKey();
        if (ecdsa is null)
        {
            server.AddSigningCertificate(certificate);
            return;
        }

        // An X509SecurityKey cannot sign with ES256 — Microsoft.IdentityModel
        // only builds RSA signature providers from a certificate — so the key
        // is handed over as the ECDSA key it is, keeping the certificate
        // thumbprint as the key identifier published in the JWKS.
        server.AddSigningCredentials(new SigningCredentials(
            new ECDsaSecurityKey(ecdsa) { KeyId = certificate.Thumbprint },
            ecdsa.KeySize switch
            {
                <= 256 => SecurityAlgorithms.EcdsaSha256,
                <= 384 => SecurityAlgorithms.EcdsaSha384,
                _ => SecurityAlgorithms.EcdsaSha512,
            }));
    }
}
