using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Networking;
using Sufficit.Identity.UI.Management.Clients;

namespace Sufficit.Identity.UI.Management.Networking;

/// <summary>
/// Circuit-safe adapter over the canonical management API boundary. It resolves a fresh scope per operation and never reads persistence directly.
/// </summary>
public sealed class ManagementTrustedProxiesDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementTrustedProxiesDataSource> logger)
{
    public Task<ManagementDataResult<ManagementTrustedProxies>> GetAsync(
        CancellationToken cancellationToken = default) => ExecuteAsync(
        (service, context) => service.GetAsync(context, cancellationToken),
        "Trusted proxies", cancellationToken);

    public Task<ManagementDataResult<ManagementTrustedProxies>> SaveAsync(
        SaveTrustedProxies command,
        CancellationToken cancellationToken = default) => ExecuteAsync(
        (service, context) => service.SaveAsync(command, context, cancellationToken),
        "Trusted proxies update", cancellationToken);

    private async Task<ManagementDataResult<T>> ExecuteAsync<T>(
        Func<ITrustedProxyManagementService, ManagementRequestContext, Task<T>> operation,
        string operationName, CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var service = scope.ServiceProvider.GetRequiredService<ITrustedProxyManagementService>();
            var state = await authenticationStateProvider.GetAuthenticationStateAsync();
            var context = new ManagementRequestContext(state.User,
                Activity.Current?.Id ?? $"management-ui-{Guid.NewGuid():N}");
            return ManagementDataResult<T>.Success(await operation(service, context));
        }
        catch (ManagementValidationException exception)
        {
            return ManagementDataResult<T>.Failure(ManagementDataOutcome.Invalid, exception.Message, exception.Field);
        }
        catch (ManagementAccessException exception)
        {
            var outcome = exception.Decision.Outcome is ManagementAuthorizationOutcome.StepUpRequired
                ? ManagementDataOutcome.StepUpRequired : ManagementDataOutcome.Forbidden;
            return ManagementDataResult<T>.Failure(outcome,
                outcome is ManagementDataOutcome.StepUpRequired
                    ? "Conclua a autenticação multifator para continuar."
                    : "Sua conta não possui autoridade para consultar proxies confiáveis.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("{OperationName} timed out.", operationName);
            return ManagementDataResult<T>.Failure(ManagementDataOutcome.Unavailable, "A consulta demorou mais que o esperado.");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception)
        {
            logger.LogError(exception, "{OperationName} failed.", operationName);
            return ManagementDataResult<T>.Failure(ManagementDataOutcome.Unavailable, "O serviço não conseguiu concluir a consulta de proxies confiáveis.");
        }
    }
}
