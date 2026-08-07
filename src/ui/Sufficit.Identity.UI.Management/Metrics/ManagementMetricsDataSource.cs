using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Metrics;
using Sufficit.Identity.UI.Management.Clients;

namespace Sufficit.Identity.UI.Management.Metrics;

/// <summary>
/// Circuit-safe adapter over the canonical management API boundary. It never
/// resolves persistence stores or the external metrics backend.
/// </summary>
public sealed class ManagementMetricsDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementMetricsDataSource> logger)
{
    public Task<ManagementDataResult<ManagementMetricsOverview>> GetOverviewAsync(
        DateTime? fromUtc, DateTime? toUtc, string? clientId,
        CancellationToken cancellationToken = default) => ExecuteAsync(
        (service, context) => service.GetOverviewAsync(fromUtc, toUtc, clientId, context, cancellationToken),
        "Metrics overview", cancellationToken);

    public Task<ManagementDataResult<ManagementMetricsConfiguration>> GetConfigurationAsync(
        CancellationToken cancellationToken = default) => ExecuteAsync(
        (service, context) => service.GetConfigurationAsync(context, cancellationToken),
        "Metrics configuration", cancellationToken);

    public Task<ManagementDataResult<ManagementMetricsConfiguration>> UpdateConfigurationAsync(
        SaveManagementMetricsConfiguration command,
        CancellationToken cancellationToken = default) => ExecuteAsync(
        (service, context) => service.UpdateConfigurationAsync(command, context, cancellationToken),
        "Metrics configuration update", cancellationToken);

    private async Task<ManagementDataResult<T>> ExecuteAsync<T>(
        Func<IMetricsManagementService, ManagementRequestContext, Task<T>> operation,
        string operationName, CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var service = scope.ServiceProvider.GetRequiredService<IMetricsManagementService>();
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
                    : "Sua conta não possui autoridade para consultar métricas.");
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
            return ManagementDataResult<T>.Failure(ManagementDataOutcome.Unavailable, "O serviço não conseguiu concluir a consulta de métricas.");
        }
    }
}
