using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sufficit.Identity.Vault;

/// <summary>
/// Exercises the selected KEK during host startup. A configuration that can
/// wrap but cannot unwrap is unusable and therefore prevents readiness.
/// </summary>
internal sealed class VaultKekReadinessService : IHostedService
{
    private readonly IVaultKeyEncryptionKeySource _keySource;
    private readonly ILogger<VaultKekReadinessService> _logger;

    public VaultKekReadinessService(
        IVaultKeyEncryptionKeySource keySource,
        ILogger<VaultKekReadinessService> logger)
    {
        _keySource = keySource;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var probe = RandomNumberGenerator.GetBytes(32);
        byte[]? wrapped = null;
        byte[]? unwrapped = null;
        try
        {
            wrapped = _keySource.Wrap(probe);
            unwrapped = _keySource.Unwrap(wrapped);
            if (!CryptographicOperations.FixedTimeEquals(probe, unwrapped))
            {
                throw new CryptographicException(
                    "The configured vault KEK failed its startup round-trip probe.");
            }

            _logger.LogInformation(
                "Vault KEK {KeyIdentifier} passed the startup readiness probe.",
                _keySource.KeyIdentifier);
            return Task.CompletedTask;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(probe);
            if (wrapped is not null) CryptographicOperations.ZeroMemory(wrapped);
            if (unwrapped is not null) CryptographicOperations.ZeroMemory(unwrapped);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) =>
        Task.CompletedTask;
}
