using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sufficit.Identity.Vault;

/// <summary>Completes elapsed signing-key overlap windows on every replica.
/// The database lease ensures only one replica journals each transition.</summary>
internal sealed class VaultSigningKeyLifecycleService : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);
    private readonly IKeyVault _vault;
    private readonly VaultOptions _options;
    private readonly ILogger<VaultSigningKeyLifecycleService> _logger;

    public VaultSigningKeyLifecycleService(
        IKeyVault vault,
        VaultOptions options,
        ILogger<VaultSigningKeyLifecycleService> logger)
    {
        _vault = vault;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await _vault.RetireSigningKeysAsync(
                    _options.SigningKeyName,
                    stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (InvalidOperationException exception)
            {
                _logger.LogDebug(
                    exception,
                    "Signing-key retirement deferred because another replica owns the lifecycle lease.");
            }
            catch (Exception exception)
            {
                _logger.LogError(
                    exception,
                    "Signing-key retirement pass failed; the previous key remains excluded after its overlap deadline and the pass will retry.");
            }

            await Task.Delay(Interval, stoppingToken);
        }
    }
}
