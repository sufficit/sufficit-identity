using System.Diagnostics;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Application.Diagnostics;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Database;
using Sufficit.Identity.UI.Management.Clients;

namespace Sufficit.Identity.UI.Management.Database;

/// <summary>
/// Circuit-safe adapter over the canonical database monitoring service.
/// </summary>
public sealed class ManagementDatabaseDataSource(
    IServiceScopeFactory scopeFactory,
    AuthenticationStateProvider authenticationStateProvider,
    ILogger<ManagementDatabaseDataSource> logger)
{
    public async Task<ManagementDataResult<DatabaseRuntimeSnapshot>> GetAsync(
        CancellationToken cancellationToken = default)
    {
        try
        {
            var authentication =
                await authenticationStateProvider.GetAuthenticationStateAsync();
            var context = new ManagementRequestContext(
                authentication.User,
                Activity.Current?.Id ?? $"management-ui-{Guid.NewGuid():N}");
            await using var scope = scopeFactory.CreateAsyncScope();
            var service = scope.ServiceProvider
                .GetRequiredService<IDatabaseMonitoringService>();
            return ManagementDataResult<DatabaseRuntimeSnapshot>.Success(
                await service.GetAsync(context, cancellationToken));
        }
        catch (ManagementAccessException exception)
        {
            var outcome = exception.Decision.Outcome is
                ManagementAuthorizationOutcome.StepUpRequired
                    ? ManagementDataOutcome.StepUpRequired
                    : ManagementDataOutcome.Forbidden;
            return ManagementDataResult<DatabaseRuntimeSnapshot>.Failure(
                outcome,
                outcome is ManagementDataOutcome.StepUpRequired
                    ? "Conclua a autenticação multifator para continuar."
                    : "Sua conta não possui a capability necessária.");
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("Database telemetry query timed out.");
            return ManagementDataResult<DatabaseRuntimeSnapshot>.Failure(
                ManagementDataOutcome.Unavailable,
                "A telemetria demorou mais que o esperado. Tente novamente.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Database telemetry failed in the embedded management module.");
            return ManagementDataResult<DatabaseRuntimeSnapshot>.Failure(
                ManagementDataOutcome.Unavailable,
                "O runtime não conseguiu informar o estado do banco de dados.");
        }
    }
}
